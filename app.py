import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    bought = db.execute("SELECT symbol,sum(shares),price FROM purchase where user_id = ? GROUP BY (symbol) HAVING sum(shares) > 0",session["user_id"])
    cash = db.execute("SELECT cash from users WHERE id = ?",session["user_id"])
    total = cash[0]["cash"]
    for symbol in bought:
        total += symbol["sum(shares)"] * symbol["price"]

    return render_template("index.html", bought=bought,lookup=lookup,usd = usd, cash=cash[0],total = total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)

        details=lookup(request.form.get("symbol"))
        if not details:
            return apology("invalid symbol",400)

        if not request.form.get("shares"):
            return apology("missing shares", 403)

        if not request.form.get("shares").isdigit():
            return apology("invalid shares", 400)



        cash = db.execute("SELECT cash FROM users WHERE id = ?",session["user_id"])

        shares = request.form.get("shares")
        amt = int(shares) * details["price"]
        if amt > cash[0]["cash"]:
            return apology("can't afford",400)

        db.execute("INSERT into purchase (user_id,symbol,shares,price) VALUES (?,?,?,?)" ,session["user_id"],details["symbol"],shares ,details["price"])
        db.execute("UPDATE users SET cash = ? WHERE id = ?",cash[0]["cash"] - amt,session["user_id"])
        flash("Bought!")
        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT symbol, shares, price, date from purchase where user_id = ? ORDER BY date",session["user_id"])
    return render_template("history.html",history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("missing symbol",400)

        details = lookup(symbol)
        if not details:
            return apology("invalid symbol",400)

        name = details["name"]
        price = usd(details["price"])
        symbl = details["symbol"]

        return render_template("quoted.html",name=name, price=price, symbl=symbl)

    return render_template("quote.html")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        name = request.form.get("username")
        if not name:
            return apology("please enter a username",400)

        username = db.execute("SELECT * FROM users WHERE username = ?",name)
        if len(username) != 0 and name == username[0]["username"]:
            return apology("username is not available",400)

        password = request.form.get("password")
        if not password:
            return apology("please enter a password",400)

        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("please re-enter the password",400)

        if password != confirmation:
            return apology("passwords do not match")

        db.execute("INSERT INTO users (username,hash) VALUES (?,?)" ,name,generate_password_hash(password,method='pbkdf2:sha256', salt_length=8))
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)
        session["user_id"] = rows[0]["id"]

        flash("Registered!")

        return redirect("/")


    return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)

        details = lookup(request.form.get("symbol"))
        if not details:
            return apology("invalid symbol",400)

        if not request.form.get("shares"):
            return apology("missing shares", 403)

        shares = request.form.get("shares")
        shares = int(shares)
        existing_shares = db.execute("SELECT sum(shares) from purchase where (user_id,symbol) = (?,?) GROUP BY symbol",session["user_id"],request.form.get("symbol"))
        if shares > existing_shares[0]["sum(shares)"]:
            return apology("too many shares", 400)

        db.execute("INSERT into purchase(user_id,symbol,price,shares) VALUES (?,?,?,?)",session["user_id"],request.form.get("symbol"),details["price"],-shares)

        cash = db.execute("SELECT cash FROM users WHERE id = ?",session["user_id"])
        amt = shares * details["price"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?",cash[0]["cash"] + amt,session["user_id"])
        flash("Sold!")
        return redirect("/")

    symbols = db.execute("SELECT symbol FROM purchase where user_id = ? GROUP BY symbol HAVING sum(shares)>0",session["user_id"])
    return render_template("sell.html",symbols = symbols)
