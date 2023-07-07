const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const schema = new mongoose.Schema(
  {
    name: {
      type: String,
      default: "user",
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    password: {
      type: String,
      default: "",
      trim: true,
    }
  },
  {
    timestamps: true,
  }
);

schema.pre("save", async function (next) {
  if (this.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

schema.methods.comparePassword = async function (password) {
  const isMatch = await bcrypt.compare(password, this.password);
  return isMatch;
};

schema.methods.encryptPassword = async function (password) {
  const salt = await bcrypt.genSalt(10);
  const passwords = await bcrypt.hash(password, salt);
  return passwords;
};

const model = mongoose.model("user", schema);
module.exports = model;
