exports.responseHandler = (statusCode, body) => {
  return {
    headers: {
      'Content-Type': 'application/json',
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": true,
    },
    statusCode : statusCode,
    body: JSON.stringify(body),
  };
};