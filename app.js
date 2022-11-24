const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");

const databasePath = path.join(__dirname, "userData.db");

const app = express();

app.use(express.json());

let database = null;

const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    });

    app.listen(3000, () =>
      console.log("Server Running at http://localhost:3000/")
    );
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

const validatePassword = (password) => {
  return password.length > 4;
};

// API:1 => Path: /register/
// Scenario 1 => If the username already exists, Response => Status code: 400, Status text: User already exists
// Scenario 2 => If the registrant provides a password with less than 5 characters, Response => Status code: 400, Status text: Password is too short
// Scenario 3 => Successful registration of the registrant, Response => Status code: 200, Status text: User created successfully
app.post("/register/", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  //Encrypting Password
  const hashedPassword = await bcrypt.hash(password, 10);
  //Checking If user already exits
  const selectUserQuery = `
  SELECT 
    * 
  FROM 
    user 
  WHERE 
    username = '${username}';`;
  const databaseUser = await database.get(selectUserQuery);

  if (databaseUser === undefined) {
    //create user in user table
    const createUserQuery = `
     INSERT INTO
      user (username, name, password, gender, location)
     VALUES
      (
       '${username}',
       '${name}',
       '${hashedPassword}',
       '${gender}',
       '${location}'  
      );`;
    if (validatePassword(password)) {
      await database.run(createUserQuery);
      response.send("User created successfully"); //Scenario 3
    } else {
      response.status(400);
      response.send("Password is too short"); //Scenario 2
    }
  } else {
    response.status(400);
    response.send("User already exists"); //Scenario 1
  }
});

// API:2 => Path: /login/
// Scenario 1 => If an unregistered user tries to login, Response => Status code: 400, Status text: Invalid user
// Scenario 2 => If the user provides incorrect password, Response => Status code: 400, Status text: Invalid password
// Scenario 3 => Successful login of the user, Response => Status code: 200, Status text: Login success!
app.post("/login/", async (request, response) => {
  const { username, password } = request.body;
  //Checking If user already exits
  const selectUserQuery = `
  SELECT 
    * 
  FROM 
    user 
  WHERE 
    username = '${username}';`;
  const databaseUser = await database.get(selectUserQuery);

  if (databaseUser === undefined) {
    response.status(400);
    response.send("Invalid user"); //Scenario 1
  } else {
    const isPasswordMatched = await bcrypt.compare(
      password,
      databaseUser.password
    );
    if (isPasswordMatched === true) {
      response.send("Login success!"); //Scenario 3
    } else {
      response.status(400);
      response.send("Invalid password"); //Scenario 2
    }
  }
});

// API:3 => /change-password/
// Scenario 1 => If the user provides incorrect current password, Response => Status code: 400, Status text: Invalid current password
// Scenario 2 => If the user provides new password with less than 5 characters, Response => Status code: 400, Status text: Password is too short
// Scenario 3 => Successful password update, Response => Status code: 200, Status text: Password updated
app.put("/change-password/", async (request, response) => {
  const { username, oldPassword, newPassword } = request.body;
  //Checking If user already exits
  const checkUserQuery = `
  SELECT 
     * 
  FROM 
     user 
  WHERE 
     username = '${username}';`;
  const checkUserQueryResponse = await database.get(checkUserQuery);
  if (checkUserQueryResponse === undefined) {
    response.status(400);
    response.send("Invalid user"); //// Scenario 4 => invalid user
  } else {
    const isPasswordMatched = await bcrypt.compare(
      oldPassword,
      checkUserQueryResponse.password
    );
    if (isPasswordMatched === true) {
      if (validatePassword(newPassword)) {
        //Encrypting New Password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        //Updating Old Password to New Password
        const updatePasswordQuery = `
          UPDATE
            user
          SET
            password = '${hashedPassword}'
          WHERE
            username = '${username}';`;
        const user = await database.run(updatePasswordQuery);
        response.send("Password updated"); //Scenario 3
      } else {
        response.status(400);
        response.send("Password is too short"); //Scenario 2
      }
    } else {
      response.status(400);
      response.send("Invalid current password"); //Scenario 1
    }
  }
});

module.exports = app;
