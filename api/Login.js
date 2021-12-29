const { connection } = require("../database/connection");
const validator = require("validator");
const jwt = require("jsonwebtoken")
const config = require("../config/config.json");
const { responseHandler } = require("../responseHandler/index");

module.exports.login = async (event) => {
  let { email, password } = JSON.parse(event.body);
  if (!validator.isEmail(email.trim()))
    return responseHandler(401, { message: "Email is not valid" });
  else if (!password.trim().length)
    return responseHandler(401, { message: "Please Add Password" });

  return new Promise((resolve, reject) => {
    let sqlQuery = config.settings.query.fetchUserDetail;
    let param = [email];
    console.log("email", email)
    connection.query(sqlQuery, param, function (err, result) {
      if (result && result[0].length > 0) {
        var userDetails = result[0][0];
        console.log("userDetails", userDetails)
          if (userDetails.password === password) {
            let token;
            let isBrandUser = userDetails.userType === 'brand' ? 1 : 0;
            token = jwt.sign(
              {
                id: userDetails.id,
                email: email,
                isBrandUser: isBrandUser
              },
              config.settings.JWT.secretKey,
              { expiresIn: config.settings.JWT.expiration }
            );
            console.log("token", token)
            delete userDetails.password;
            sqlQuery = config.settings.query.insertUserSession;
            param = [userDetails.id, token, isBrandUser];
            connection.query(sqlQuery, param, function (err, result) {
              if (result) {
                console.log("result", result)
                userDetails["token"] = token;
                resolve(userDetails);
              } else {
                return reject(err);
              }
            });
          } else {
            reject({
              message: config.settings.success.messages.passwordIncorrect,
            });
          }
      } else {
        reject({ message: config.settings.success.messages.emailNotFound });
      }
    });
  })
    .then((data) => {
      console.log("data one ==", data);
      return responseHandler(200, {
        data,
        message: "Logged in successfull.",
      });
    })
    .catch((err) => {
      return responseHandler(400, {message : err.message});
    });
};

module.exports.logout = async (event) => {

  return new Promise((resolve, reject) => {

    let token = event.headers.Authorization.toString().split(' ')[1]
    console.log("token",token)
    let decoded = jwt.decode(token);
    let userId = parseInt(decoded.id);
    let isBrandUser = parseInt(decoded.isBrandUser)
    console.log(decoded);
    if (userId) {
      let sqlQuery = config.settings.query.logoutUser;;
      let param = [userId, token];
      connection.query(sqlQuery, param, function (err, result) {
          if (result) {
            resolve({ message: "successfully logged out" });
          } else {
            reject({message: config.settings.errors[500].afterQuery})
          }
        }

      )}
  })
    .then((data) => {
      console.log("data one ==", data);
      return responseHandler(200, {
        data
      });
    })
    .catch((err) => {
      return responseHandler(400, err);
    });
};

module.exports.helloWorld = async (event) =>{
  return responseHandler(200, {message:'Hello World'});
}