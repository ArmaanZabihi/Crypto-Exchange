import os
import requests
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from cs50 import SQL
import datetime
import sqlite3
from extension import apology, login_required, usd, lookup
from functools import wraps

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

conn = sqlite3.connect("your_database.db")
db = conn.cursor()
db.execute(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, hash TEXT)")
conn.commit()

API_KEY = 'CG-mAxxE5yH4iuQ1uVqcY9tFRXG'


@app.route('/get/coins/list', methods=["GET"])
def get_coins():
    if request.method == "GET":
        url = 'https://api.coingecko.com/api/v3/coins/list'
        headers = {'accept': 'application/json',
                   'X-CoinGecko-API-Key': API_KEY}
        params = {'include_platform': 'false'}

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()
            coins_data = [{'id': coin['id'], 'symbol': coin['symbol'],
                           'name': coin['name']} for coin in data]
            return jsonify(coins_data)
        else:
            return "Error: Unable to fetch data", 400


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if len(password) < 4:
            return apology("Password must be greater than 4 characters.")
        if not password:
            return apology("Must provide a password")
        if not confirmation:
            return apology("Must provide a confirmation")
        if password != confirmation:
            return apology("Passwords don't match")

        hash = generate_password_hash(password)

        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", (username, hash))
            conn.commit()
        except sqlite3.IntegrityError:
            return apology("Username already exists")

        user_id = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
        session["user_id"] = user_id

        return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            return apology("Must provide a username", 403)
        elif not password:
            return apology("Must provide a password", 403)

        user_info = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user_info and check_password_hash(user_info["hash"], password):
            session["user_id"] = user_info["id"]
            return redirect("/")
        else:
            return apology("Invalid username and/or password", 403)

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "GET":
        return render_template("add_cash.html")
    else:
        new_cash = request.form.get("new_cash")

        if not new_cash:
            return apology("Input the amount of money")
        user_id = session["user_id"]
        user_cash_db = db.execute(
            "SELECT cash FROM users WHERE id = :id", id=user_id)
        user_cash = user_cash_db[0]["cash"]

        uptd_cash = user_cash + float(new_cash)

        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   uptd_cash, user_id)
        conn.commit()

        flash("Added cash successfully!")

        return redirect("/")


@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]
    transactions_db = db.execute(
        "SELECT * FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", transactions=transactions_db)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("Must provide a symbol")
        stock = lookup(symbol.upper())

        if stock is None:
            return apology("Symbol does not exist")
        if shares < 0:
            return apology("Negative shares not allowed")

        transaction_value = shares * stock["price"]

        user_id = session["user_id"]
        user_cash_db = db.execute(
            "SELECT cash FROM users WHERE id = :id", id=user_id)
        user_cash = user_cash_db[0]["cash"]

        if user_cash < transaction_value:
            return apology("Not enough money to make this purchase")

        uptd_cash = user_cash - transaction_value

        date = datetime.datetime.now()

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)",
                   user_id, stock["symbol"], shares, stock["price"], date)

        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   uptd_cash, user_id)

        conn.commit()

        flash("Bought!")

        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        user_id = session["user_id"]
        symbols_user = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = :id GROUP BY symbol HAVING SUM(shares) > 0", id=user_id
        )
        return render_template("sell.html", symbols=[row["symbol"] for row in symbols_user])
    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("Must provide a symbol")
        stock = lookup(symbol.upper())

        if stock is None:
            return apology("Symbol does not exist")
        if shares < 0:
            return apology("Negative shares not allowed")

        transaction_value = shares * stock["price"]

        user_id = session["user_id"]
        user_cash_db = db.execute(
            "SELECT cash FROM users WHERE id = :id", id=user_id)
        user_cash = user_cash_db[0]["cash"]

        user_shares = db.execute(
            "SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = :id AND symbol = :symbol",
            id=user_id, symbol=symbol,
        )
        user_shares_real = user_shares[0]["total_shares"]

        if shares > user_shares_real:
            return apology("You don't have enough shares to sell")

        uptd_cash = user_cash + transaction_value

        date = datetime.datetime.now()

        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)",
            user_id, stock["symbol"], -1 * shares, stock["price"], date,
        )

        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   uptd_cash, user_id)

        conn.commit()

        flash("Sold!")

        return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Must provide a symbol")
        stock = lookup(symbol.upper())

        if stock is None:
            return apology("Symbol does not exist")

        return render_template("quoted.html", name=stock["name"], price=usd(stock["price"]), symbol=stock["symbol"])


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]

    transactions_db = db.execute(
        "SELECT symbol, SUM(shares) AS shares, AVG(price) AS price FROM transactions WHERE user_id = ?", user_id)
    cash_db = db.execute("SELECT cash from users WHERE id = ?", user_id)
    cash = cash_db[0]["cash"]

    total = cash

    for transaction in transactions_db:
        total += transaction["shares"] * transaction["price"]

    return render_template("index.html", database=transactions_db, cash=usd(cash), total=usd(total))


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


if __name__ == '__main__':
    app.run(debug=True)


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"

# GET current Data for BTC


url = 'https://api.coingecko.com/api/v3/coins/bitcoin?'
headers = {
    'accept': 'application/json'
}

params = {
    'localization': True,
    'tickers': True,
    'market_data': True,
    'community_data': True,
    'developer_data': True,
    'sparkline': True
}

response = requests.get(url, headers=headers, params=params)

if response.status_code == 200:
    data = response.json()
    # Process the JSON response data here
    print(data)
else:
    print(f'Error: {response.status_code}')
    print(response.text)

# Lookup


def lookup():
    url = 'https://api.coingecko.com/api/v3/coins/list'

    try:
        response = requests.get(url, headers={'accept': 'application/json'})
        response.raise_for_status()

        data = response.json()
        coins_data = [{'id': coin['id'], 'symbol': coin['symbol'],
                       'name': coin['name']} for coin in data]

        return coins_data
    except (requests.RequestException, ValueError, KeyError, IndexError):
        return None
