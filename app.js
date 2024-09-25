const express = require("express");
const {open} = require("sqlite");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");
const dotenv = require("dotenv");
const { v4: uuidv4 } = require("uuid");

dotenv.config();

const app = express();
app.use(express.json());

const databasePath = path.join(__dirname, "todoApplications.db");
let database = null;

const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database
    });
    
    app.listen(3000, () => {
      console.log("Server Running at http://localhost:3000/");
    });

  } catch (error) {
    console.error(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

// User Registration
app.post("/register", async (request, response) => {
  const { username, email, password } = request.body; // Change request to request.body
  console.log(username, password);
  try {
    const checkEmailQuery = `SELECT * FROM user WHERE email = ?;`;
    const existingUser = await database.get(checkEmailQuery, [email]);
    
    if (existingUser) {
      console.log(`User already exists with email: ${email}`);
      return response.status(400).send("User already exists with this email.");
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const userId = uuidv4(); // Generate a new UUID
      const createUserQuery = `INSERT INTO user (id, username, email, password) VALUES (?, ?, ?, ?);`; // Use placeholders correctly
      await database.run(createUserQuery, [userId, username, email, hashedPassword]); // Pass the values directly
      response.status(201).send("User registered successfully");
    }
  } catch (error) {
    console.error(`Error during registration: ${error.message}`);
    response.status(500).send("Internal server error during registration");
  }
});



// User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;


  try {
    const user = await database.get(`SELECT * FROM user WHERE email = ?;`, [email]);
    if (!user) {
      console.log("User not found");
      return res.status(400).send("Invalid email or password");
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (passwordMatch) {
      const token = jwt.sign({ userId: user.id, username: user.username }, process.env.SECRET_KEY);
      return res.send({ jwtToken: token });
    } else {
      console.log("Incorrect password");
      return res.status(400).send("Invalid email or password");
    }
  } catch (error) {
    console.error(`Login error: ${error.message}`);
    return res.status(500).send("Internal server error during login");
  }
});

// Authentication Middleware
const authentication = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Optional chaining
  if (!token) {
    return res.status(401).send("Authorization token is required");
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, payload) => {
    if (err) {
      return res.status(401).send("Invalid JWT Token");
    }
    req.userId = payload.userId;
    next();
  });
};

// Get Profile
app.get("/profile", authentication, async (req, res) => {
  try {
    const user = await database.get(`SELECT username, email FROM user WHERE id = ?;`, [req.userId]);
    if (!user) {
      return res.status(404).send("User not found");
    }
    res.send(user);
  } catch (error) {
    console.error(`Profile retrieval error: ${error.message}`);
    res.status(500).send("Internal server error during profile retrieval");
  }
});

// Update Profile
app.put("/profile", authentication, async (req, res) => {
  const { username, email, password } = req.body;

  try {
    let updateQuery = `UPDATE user SET `;
    const params = [];

    if (username) {
      updateQuery += `username = ?, `;
      params.push(username);
    }
    if (email) {
      updateQuery += `email = ?, `;
      params.push(email);
    }
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateQuery += `password = ?, `;
      params.push(hashedPassword);
    }

    updateQuery = updateQuery.slice(0, -2); // Remove the trailing comma and space
    updateQuery += ` WHERE id = ?;`;
    params.push(req.userId);

    await database.run(updateQuery, params);
    res.send("Profile Updated");
  } catch (error) {
    console.error(`Profile update error: ${error.message}`);
    res.status(500).send("Internal server error during profile update");
  }
});

// Create Todo
app.post("/todos", authentication, async (req, res) => {
  const { todo, status = "pending" } = req.body;
  const userId = req.userId;
  const todoId = uuidv4(); // Generate a new UUID for the todo

  try {
    const createTodoQuery = `INSERT INTO todo (id, userId, todo, status) VALUES (?, ?, ?, ?);`;
    await database.run(createTodoQuery, [todoId, userId, todo, status]);
    res.status(201).send("Todo Successfully Added");
  } catch (error) {
    console.error(`Todo creation error: ${error.message}`);
    res.status(500).send("Internal server error during todo creation");
  }
});

// Get Todos
app.get("/todos", authentication, async (req, res) => {
  const userId = req.userId;

  try {
    const todos = await database.all(`SELECT * FROM todo WHERE userId = ?;`, [userId]);
    res.send(todos);
  } catch (error) {
    console.error(`Todos retrieval error: ${error.message}`);
    res.status(500).send("Internal server error during todos retrieval");
  }
});

// Update Todo
app.put("/todos/:todoId", authentication, async (req, res) => {
  const { todoId } = req.params;
  const { todo, status } = req.body;

  try {
    const updateTodoQuery = `
      UPDATE todo 
      SET todo = COALESCE(?, todo), 
          status = COALESCE(?, status)
      WHERE id = ? AND userId = ?;`;

    await database.run(updateTodoQuery, [todo, status, todoId, req.userId]);
    res.send("Todo Updated Successfully");
  } catch (error) {
    console.error(`Todo update error: ${error.message}`);
    res.status(500).send("Internal server error during todo update");
  }
});

// Delete Todo
app.delete("/todos/:todoId", authentication, async (req, res) => {
  const { todoId } = req.params;

  try {
    const deleteTodoQuery = `DELETE FROM todo WHERE id = ? AND userId = ?;`;
    await database.run(deleteTodoQuery, [todoId, req.userId]);
    res.send("Todo Deleted");
  } catch (error) {
    console.error(`Todo deletion error: ${error.message}`);
    res.status(500).send("Internal server error during todo deletion");
  }
});


initializeDbAndServer();
