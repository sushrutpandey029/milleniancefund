import express from "express";
import dotenv from "dotenv";
import hbs from "hbs";
import path from "path";
import session from "express-session";
import MySQLStore from "express-mysql-session";
import sequelize from "./Database/MySql_connection.js";
import route from "./Routes/Admin_Route.js";
import { fileURLToPath } from "url";
import { EventEmitter } from "events";
import flash from "connect-flash";

// Increase the max listeners to prevent warnings
EventEmitter.defaultMaxListeners = 20;

// Initialize dotenv
dotenv.config();

const port = process.env.PORT || 4000;
const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure session store
const MySQLStoreSession = MySQLStore(session);

const sessionStore = new MySQLStoreSession({
  host: "127.0.0.1",
  port: 3306,
  user: "root",
  password: "root@123",
  database: "Milleniance_Account",
});

app.use(
  session({
    key: "session_cookie_name",
    secret: process.env.SESSION_SECRET || "tomharry@123",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);

app.use(flash());

// Middleware to pass flash messages to views
app.use((req, res, next) => {
    res.locals.successMessage = req.flash("success");
    res.locals.errorMessage = req.flash("error");
    next();
});

// Set up the view engine
app.set("view engine", "html");
app.engine("html", hbs.__express);

app.set("Views", path.join(__dirname, "Views"));
// Static files
app.use(express.static(path.join(__dirname, 'Views', 'public', 'assets')));

hbs.registerPartials(path.join(__dirname, 'Views','commonTemplate'));

app.use("/images", express.static(path.join(__dirname, "Views", "public", "images")));

// Routes
app.use("/", route);

// Start server
const startServer = () => {
  sequelize
    .sync()
    .then(() => {
      app.listen(port, () => {
        console.log(`Server running on port: http://localhost:${port}`);
      });
    })
    .catch((err) => {
      console.error("MySQL connection failed:", err);
    });
};

startServer();
