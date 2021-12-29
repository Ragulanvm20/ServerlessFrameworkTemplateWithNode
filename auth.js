const { connection } = require("./database/connection");
var jwt = require("jsonwebtoken");
var config = require("./config/config.json");
module.exports.handler = (evt, ctx, callback) => {
    console.log("test");
    console.log("event", evt)
    const token = evt.headers.Authorization.toString().split(' ')[1];
    console.log("token", token)

    if (!token) {
        return callback("Unauthorized");
    }
    jwt.verify(token, config.settings.JWT.secretKey, function (err, decoded) {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return callback("Token Expired");
            } else {
                return callback("Token Malformed");
            }
        }
        else{
            var userId = decoded.id;
            let sqlQuery = "SELECT * FROM  session WHERE jwtToken = ? and userId = ? LIMIT 1"
            let param = [token, userId]
            connection.query(sqlQuery, param, function (err, result){
                if(result){
                    var data = result;
                    if (data.length > 0) {
                        var data = result[0];
                        if(data.jwtToken != token) {

                            return callback("Token Not authenticated");
                        }
                        else{
                            callback(null, buildAllowAllPolicy(evt, data.firstName));
                        }
                    } else{
                        return callback("Token Not authenticated");
                    }
                }
                else{
                    return callback("Data not found");
                }
            })
        }
    })
};

function buildAllowAllPolicy(evt, principalId) {
    const tmp = evt.methodArn.split(":");
    const apiGatewayArnTmp = tmp[5].split("/");
    const awsAccountId = tmp[4];
    const awsRegion = tmp[3];
    const restApiId = apiGatewayArnTmp[0];
    const stage = apiGatewayArnTmp[1];
    console.log(evt.methodArn.split(":"))
    const apiArn = `arn:aws:execute-api:${awsRegion}:${awsAccountId}:${restApiId}/${stage}/*/*`;
    const policy = {
        principalId : "user",
        policyDocument: {
            Version: "2012-10-17",
            Statement: [
                {
                    Action: "execute-api:Invoke",
                    Effect: "Allow",
                    Resource: [apiArn]
                }
            ]
        }
    };

    return policy;
}
