package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
)

var db *sql.DB
var myTemplate *template.Template
var store = sessions.NewCookieStore([]byte("secretLogin"))

func main() {
	var err error
	db, err = sql.Open("mysql", "root:@tcp(localhost:3306)/bankapp")
	if err != nil {
		fmt.Println("Error connecting to the database")
		panic(err.Error())
	} else {
		fmt.Println("Connected to the database")
	}
	defer db.Close()

	myTemplate, _ = template.ParseGlob("templates/*.html")

	http.HandleFunc("/", home)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/dashboard", dashboard)
	http.HandleFunc("/balance", balance)
	http.HandleFunc("/deposit", deposit)
	http.HandleFunc("/withdraw", withdraw)
	http.HandleFunc("/transactions", transactions)
	http.HandleFunc("/processSignup", processSignup)
	http.HandleFunc("/processLogin", processLogin)
	http.HandleFunc("/processDeposit", processDeposit)
	http.HandleFunc("/processWithdraw", processWithdraw)

	fmt.Println("running")
	http.ListenAndServe("localhost:8080", nil)

}

func home(w http.ResponseWriter, r *http.Request) {
	myTemplate.ExecuteTemplate(w, "index.html", nil)
}

func signup(w http.ResponseWriter, r *http.Request) {
	myTemplate.ExecuteTemplate(w, "signup.html", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	myTemplate.ExecuteTemplate(w, "login.html", nil)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-login")
	session.Options.MaxAge = -1
	session.Save(r, w)
	myTemplate.ExecuteTemplate(w, "logout.html", nil)
}

func dashboard(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-login")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	username := session.Values["username"]
	if username == nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	myTemplate.ExecuteTemplate(w, "dashboard.html", nil)
}

func balance(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-login")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	username := session.Values["username"]
	if username == nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	selectStatement := "SELECT sum(if(transaction_type = 'Withdraw', amount * -1, amount)) AS balance FROM transactions WHERE username = ? GROUP BY username;"
	var balance string
	row := db.QueryRow(selectStatement, username)
	err = row.Scan(&balance)
	if err != nil {
		fmt.Println("There was an error getting the balance")
		return
	}
	myTemplate.ExecuteTemplate(w, "balance.html", balance)
}

func deposit(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-login")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	username := session.Values["username"]
	if username == nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	myTemplate.ExecuteTemplate(w, "deposit.html", nil)
}

func withdraw(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-login")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	username := session.Values["username"]
	if username == nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	myTemplate.ExecuteTemplate(w, "withdraw.html", nil)
}

func transactions(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-login")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	username := session.Values["username"]
	if username == nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	selectStatement := "SELECT transaction_type, amount FROM transactions WHERE username = ?;"

	rows, err := db.Query(selectStatement, username)
	if err != nil {
		fmt.Println("There was a problem getting the transactions")
		return
	}
	defer rows.Close()
	var transactions []string
	for rows.Next() {
		var transactionType string
		var amount float64
		rows.Scan(&transactionType, &amount)
		sign := ""
		if transactionType == "Withdraw" {
			sign = "-"
		}
		transaction := fmt.Sprintf("$%s%.2f %s", sign, amount, transactionType)
		transactions = append(transactions, transaction)
	}
	myTemplate.ExecuteTemplate(w, "transactions.html", transactions)
}

func processSignup(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.FormValue("txtUsername")
	password := r.FormValue("txtPassword")
	if username == "" || password == "" {
		myTemplate.ExecuteTemplate(w, "signup.html", "Enter a username and password")
		return
	}
	selectStatement := "select username from users where username = ?"
	row := db.QueryRow(selectStatement, username)
	var dbUsername string
	err := row.Scan(&dbUsername)
	if err != sql.ErrNoRows {
		fmt.Println("Username is taken: ", err)
		myTemplate.ExecuteTemplate(w, "signup.html", "Username is taken")
		return
	}
	var hashPassword []byte
	hashPassword, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		myTemplate.ExecuteTemplate(w, "signup.html", "There was an error with your password")
		return
	}
	var insertStatement *sql.Stmt
	insertStatement, err = db.Prepare("insert into users(username, password) values(?, ?);")
	if err != nil {
		myTemplate.ExecuteTemplate(w, "signup.html", "There was an error creating your account")
		return
	}
	defer insertStatement.Close()
	_, err = insertStatement.Exec(username, hashPassword)
	if err != nil {
		myTemplate.ExecuteTemplate(w, "signup.html", "There was an error creating your account")
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func processLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.FormValue("txtUsername")
	password := r.FormValue("txtPassword")
	var hashPassword string
	selectStatement := "select password from users where username = ?"
	row := db.QueryRow(selectStatement, username)
	err := row.Scan(&hashPassword)
	if err != nil {
		myTemplate.ExecuteTemplate(w, "login.html", "Incorrect username and password")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashPassword), []byte(password))
	if err != nil {
		myTemplate.ExecuteTemplate(w, "login.html", "Incorrect username and password")
		return
	}

	session, err := store.Get(r, "session-login")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["username"] = username
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	myTemplate.ExecuteTemplate(w, "dashboard.html", username)
}

func processWithdraw(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	withdrawAmount := r.FormValue("txtWithdrawAmount")

	session, err := store.Get(r, "session-login")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := session.Values["username"]
	var insertStatement *sql.Stmt
	insertStatement, err = db.Prepare("insert into transactions(transaction_type, amount, username) values('Withdraw', ?, ?);")
	if err != nil {
		fmt.Println("There was a problem inserting the transaction")
		return
	}
	defer insertStatement.Close()
	_, err = insertStatement.Exec(withdrawAmount, username)
	if err != nil {
		fmt.Println("There was a problem inserting the transaction")
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
}

func processDeposit(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	depositAmount := r.FormValue("txtDepositAmount")

	session, err := store.Get(r, "session-login")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := session.Values["username"]
	var insertStatement *sql.Stmt
	insertStatement, err = db.Prepare("insert into transactions(transaction_type, amount, username) values('Deposit', ?, ?);")
	if err != nil {
		fmt.Println("There was a problem inserting the transaction")
		return
	}
	defer insertStatement.Close()
	_, err = insertStatement.Exec(depositAmount, username)
	if err != nil {
		fmt.Println("There was a problem inserting the transaction")
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
}
