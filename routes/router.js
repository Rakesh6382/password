const express = require("express");
const router = new express.Router();
const userdb = require("../models/userSchema");
const bcrypt = require("bcryptjs");
const authenticate = require("../middleware/authenticate");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

const keysecret = process.env.SECRET_KEY;

// Email config
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD
  }
});

// ======================= REGISTER =======================
// ======================= REGISTER =======================
router.post("/register", async (req, res) => {
  const { fname, email, password, cpassword } = req.body;

  // 👇 Add this line here
  console.log("Received body:", req.body);

  if (!fname || !email || !password || !cpassword) {
    return res.status(422).json({ error: "Fill all the details" });
  }

  try {
    const preuser = await userdb.findOne({ email });
    if (preuser) {
      return res.status(422).json({ error: "This Email already exists" });
    } else if (password !== cpassword) {
      return res.status(422).json({ error: "Passwords do not match" });
    }

    const finalUser = new userdb({ fname, email, password, cpassword });
    const storeData = await finalUser.save();
    res.status(201).json({ message: "User registered successfully", storeData });
  } catch (error) {
    res.status(500).json({ error: "Registration failed" });
  }
});


// ======================= LOGIN =======================
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(422).json({ error: "Fill all the details" });
  }

  try {
    const userValid = await userdb.findOne({ email });
    if (!userValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, userValid.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = await userValid.generateAuthtoken();

    res.cookie("usercookie", token, {
      expires: new Date(Date.now() + 9000000),
      httpOnly: true,
      secure: false, // true only in production with HTTPS
      sameSite: "lax"
    });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// ======================= VALID USER =======================
router.get("/validuser", authenticate, async (req, res) => {
  try {
    const ValidUserOne = await userdb.findOne({ _id: req.userId });
    res.status(200).json({ user: ValidUserOne });
  } catch (error) {
    res.status(401).json({ error: "Unauthorized" });
  }
});

// ======================= LOGOUT =======================
router.get("/logout", authenticate, async (req, res) => {
  try {
    req.rootUser.tokens = req.rootUser.tokens.filter(
      (curelem) => curelem.token !== req.token
    );

    res.clearCookie("usercookie", { path: "/" });
    await req.rootUser.save();

    res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    res.status(500).json({ error: "Logout failed" });
  }
});
// ======================= SEND PASSWORD RESET LINK =======================
router.post("/sendpasswordlink", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(422).json({ error: "Please provide email" });
  }

  try {
    const userValid = await userdb.findOne({ email });

    if (!userValid) {
      return res.status(401).json({ error: "User not found" });
    }

    // Generate a reset token
    const token = jwt.sign({ _id: userValid._id }, keysecret, {
      expiresIn: "15m"
    });

    // Save token in user record (optional, for validation later)
    userValid.verifytoken = token;
    await userValid.save();

    // Send email with reset link
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Password Reset Link",
      text: `Click here to reset your password: https://passwordreset-flows.netlify.app/forgotpassword/${userValid._id}/${token}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log("Error sending email:", error);
        return res.status(500).json({ error: "Email not sent" });
      } else {
        console.log("Email sent:", info.response);
        return res.status(201).json({ message: "Email sent successfully" });
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});


module.exports = router;
