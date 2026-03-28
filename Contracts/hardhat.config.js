require("@nomicfoundation/hardhat-toolbox");
const path = require("path");

module.exports = {
  solidity: "0.8.17",
  paths: {
    sources: path.join(__dirname, "contracts"),
    artifacts: path.join(__dirname, "artifacts"),
  },
};
