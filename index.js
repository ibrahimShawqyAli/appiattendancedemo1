require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "mySuperSecretKey123!@Shawqy";

// Middleware
//  Saves timestamps in ISO 8601 UTC format
app.use(express.json());
app.use(cors());



// Connect to MongoDB
const MONGO_URL = "mongodb://mongo:iVCIvLdzcLmmsNBOjsHYhfllUTgkGsnZ@monorail.proxy.rlwy.net:14423";
console.log("Mongo URL:", MONGO_URL);
// Ensure MongoDB URI is provided
if (!process.env.MONGO_URI) {
    console.error("❌ MongoDB connection string (MONGO_URI) is missing!");
    process.exit(1); // Stop the server if no connection string is provided
}

// Connect to MongoDB using Railway Environment Variable
mongoose.connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB Connected Successfully"))
.catch(err => {
    console.error("❌ MongoDB Connection Error:", err);
    process.exit(1); // Stop the server if there is a connection failure
});


// User Schema
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    mobile: { type: String, required: true },
    department: { type: String, required: true },
    position: { type: String, required: true },
    organization: { type: String, required: true } // Organization field added
  });
  const User = mongoose.model("User", UserSchema);
  

// Location Schema
const LocationSchema = new mongoose.Schema({
  longitude: { type: Number, required: true },
  latitude: { type: Number, required: true }
});
const Location = mongoose.model("Location", LocationSchema);

// Attendance Schema
const AttendanceSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  checkType: { type: String, enum: ["check-in", "check-out"], required: true },
  longitude: { type: Number, required: true },
  latitude: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now }
});
const Attendance = mongoose.model("Attendance", AttendanceSchema);
// working time scheme
const WorkTimeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    date: { type: String, required: true }, // YYYY-MM-DD format
    workTime: { type: String, required: true } // Total work time in hours
});

const WorkTime = mongoose.model("WorkTime", WorkTimeSchema);

// Registration API
app.post("/api/register", async (req, res) => {
    const { email, password, name, mobile, department, position, organization } = req.body;

    // Email validation regex pattern
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    // Validate all required fields
    if (!email || !password || !name || !mobile || !department || !position || !organization) {
        return res.status(200).json({ status: false, message: "All fields are required" });
    }

    // Validate email format
    if (!emailRegex.test(email)) {
        return res.status(200).json({ status: false, message: "Invalid email format" });
    }

    try {
        let user = await User.findOne({ email, organization }); // Ensure unique user per organization
        if (user) return res.status(200).json({ status: false, message: "User already exists in this organization" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({ email, password: hashedPassword, name, mobile, department, position, organization });
        await user.save();

        const token = jwt.sign({ userId: user._id, organization }, JWT_SECRET, { expiresIn: "1h" });
        res.status(201).json({ status: true, message: "User registered successfully", token });
    } catch (err) {
        res.status(200).json({ status: false, message: "Server error", error: err.message });
    }
});
// test
app.get("/api/test", async (req, res) => {
 res.send('Working');
  });  
// Login API
app.post("/api/login", async (req, res) => {
    const { email, password, organization } = req.body; // Organization required for login
  
    try {
      const user = await User.findOne({ email, organization }); // Find user by email & organization
      if (!user) return res.status(200).json({ status: false, message: "Invalid credentials" });
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(200).json({ status: false, message: "Invalid credentials" });
  
      const token = jwt.sign({ userId: user._id, organization }, JWT_SECRET, { expiresIn: "1h" });
      res.json({ status: true, message: "Login successful", token });
    } catch (err) {
      res.status(200).json({ status: false, message: "Server error", error: err.message });
    }
  });  
// change the pass 
app.post("/api/change-password", async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(200).json({ status: false, message: "Invalid or missing Authorization header" });
        }

        const token = authHeader.split(" ")[1];

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            return res.status(200).json({ status: false, message: "Invalid User" });
        }

        const userId = decoded.userId;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(200).json({ status: false, message: "User not found" });
        }

        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(200).json({ status: false, message: "Old password is incorrect" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(newPassword, salt);

        user.password = hashedNewPassword;
        await user.save();

        res.status(200).json({ status: true, message: "Password changed successfully" });
    } catch (err) {
        res.status(200).json({ status: false, message: "Server error", error: err.message });
    }
});
// profile 
app.get("/api/user-profile", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(200).json({ status: false, message: "Invalid or missing Authorization header" });
        }

        const token = authHeader.split(" ")[1];

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            return res.status(200).json({ status: false, message: "Invalid User" });
        }

        const { userId, organization } = decoded;

        // Fetch user data including name
        const user = await User.findOne({ _id: userId, organization }).select("-password"); // Explicitly select fields

        if (!user) {
            return res.status(200).json({ status: false, message: "User not found" });
        }

        res.status(200).json({ 
            status: true, 
            message: "User profile retrieved", 
            user: {
                name: user.name,
                email: user.email,
                mobile: user.mobile,
                department: user.department,
                position: user.position,
                organization: user.organization
            } 
        });

    } catch (err) {
        res.status(200).json({ status: false, message: "Server error", error: err.message });
    }
});

// update profile
app.put("/api/update-profile", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        const passwordHeader = req.headers.password; // Get password from headers

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(200).json({ status: false, message: "Invalid or missing Authorization header" });
        }
        if (!passwordHeader) {
            return res.status(200).json({ status: false, message: "Password is required in headers" });
        }

        // Extract and verify token
        const token = authHeader.split(" ")[1];

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            return res.status(200).json({ status: false, message: "Invalid User" });
        }

        const userId = decoded.userId;

        // Fetch user data
        const user = await User.findById(userId);
        if (!user) {
            return res.status(200).json({ status: false, message: "User not found" });
        }

        // Verify the provided password
        const isMatch = await bcrypt.compare(passwordHeader, user.password);
        if (!isMatch) {
            return res.status(200).json({ status: false, message: "Incorrect password" });
        }

        // Extract fields from request body (excluding email and organization)
        const { name, mobile, department, position } = req.body;

        // Ensure email and organization are NOT updated
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { name, mobile, department, position }, // Do not update email or organization
            { new: true, runValidators: true }
        ).select("-password -email -organization"); // Exclude sensitive fields

        if (!updatedUser) {
            return res.status(200).json({ status: false, message: "User not found after update" });
        }

        res.status(200).json({ status: true, message: "Profile updated successfully", user: updatedUser });
    } catch (err) {
        res.status(200).json({ status: false, message: "Server error", error: err.message });
    }
});

// get attendance:
app.get("/api/attendance", async (req, res) => {
    try {
        const month = parseInt(req.headers["month"]); // Read month from headers
        const year = parseInt(req.headers["year"]);   // Read year from headers
        const authHeader = req.headers.authorization;

        // Validate headers
        if (!month || month < 1 || month > 12) {
            return res.status(400).json({ status: false, message: "Invalid or missing month (1-12)" });
        }
        if (!year || year < 2000 || year > new Date().getFullYear()) {
            return res.status(400).json({ status: false, message: "Invalid or missing year" });
        }
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ status: false, message: "Invalid or missing Authorization header" });
        }

        // Extract and verify token
        const token = authHeader.split(" ")[1];
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            return res.status(401).json({ status: false, message: "Invalid User" });
        }

        const userId = decoded.userId;

        // Calculate start and end date for the month
        const startDate = new Date(Date.UTC(year, month - 1, 1)); // First day of the month
        const today = new Date();
    //    today.setUTCHours(0, 0, 0, 0); // Reset time to start of the day (UTC)

        let endDate;
        if (year < today.getFullYear() || (year === today.getFullYear() && month < today.getMonth() + 1)) {
            // If the requested month is in the past, get the full month's data
            endDate = new Date(Date.UTC(year, month, 0)); // Last day of the month
        } else {
            // If the requested month is the current month, fetch up to today
            endDate = today;
        }

        // Fetch attendance records for the user in the given month
        const records = await Attendance.find({
            userId,
            timestamp: { $gte: startDate, $lte: endDate }
        }).sort({ timestamp: 1 }); // Sort by date ascending

        // Create a map to store attendance records
        const attendanceMap = new Map();

        // Process records to group check-in and check-out times by date
        records.forEach(record => {
            const dateKey = record.timestamp.toISOString().split("T")[0]; // Get YYYY-MM-DD
            if (!attendanceMap.has(dateKey)) {
                attendanceMap.set(dateKey, { checkIn: null, checkOut: null });
            }
            if (record.checkType === "check-in") {
                attendanceMap.get(dateKey).checkIn = record.timestamp.toISOString(); // Store UTC format
            } else if (record.checkType === "check-out") {
                attendanceMap.get(dateKey).checkOut = record.timestamp.toISOString(); // Store UTC format
            }
        });

        // Generate all days from the start of the month until the correct end date
        const formattedRecords = [];
        let currentDate = new Date(startDate);

        while (currentDate <= endDate) {
            const dateKey = currentDate.toISOString().split("T")[0]; // YYYY-MM-DD format

            if (attendanceMap.has(dateKey)) {
                // If there's a record, calculate total work hours
                const times = attendanceMap.get(dateKey);
                let totalHours = 0;
                let record_status = "hold";

                if (times.checkIn && times.checkOut) {
                    record_status = "present";
                    totalHours = (new Date(times.checkOut) - new Date(times.checkIn)) / (1000 * 60 * 60); // Convert ms to hours
                }

                formattedRecords.push({
                    date: dateKey,
                    checkIn: times.checkIn, // Keep as null if no check-in
                    checkOut: times.checkOut, // Keep as null if no check-out
                    total_hours: totalHours.toFixed(2),
                    record_status: record_status
                });
            } else if (currentDate < today) {
                // If no record and it's a past date, mark as "absence"
                formattedRecords.push({
                    date: dateKey,
                    checkIn: null, 
                    checkOut: null, 
                    total_hours: "0.00",
                    record_status: "absence"
                });
            }

            // Move to the next day
            currentDate.setUTCDate(currentDate.getUTCDate() + 1);
        }

        // Return formatted records
        res.status(200).json({
            status: true,
            message: "Attendance records retrieved",
            records: formattedRecords
        });

    } catch (err) {
        res.status(500).json({ status: false, message: "Server error", error: err.message });
    }
});

// Save Office Location API
app.post("/api/attendance", async (req, res) => {
    console.log("Headers Received:", req.headers);
    console.log("Received Request Body:", req.body);

    try {
        const { longitude, latitude, checkType } = req.body;

        if (!longitude || !latitude || !checkType) {
            return res.status(400).json({
                status: false,
                message: "Longitude, latitude, and checkType are required",
            });
        }

        const authHeader = req.headers.authorization;

        // Validate token presence
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ status: false, message: "Invalid or missing Authorization header" });
        }

        // Extract and verify token
        const token = authHeader.split(" ")[1];
        console.log("Received Token:", token);

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
            console.log("Decoded Token:", decoded);
        } catch (err) {
            console.error("JWT Verification Error:", err.message);
            return res.status(401).json({ status: false, message: "Invalid User" });
        }

        if (!decoded || !decoded.userId) {
            return res.status(401).json({ status: false, message: "Invalid User structure" });
        }

        const userId = decoded.userId;
        console.log("User ID from Token:", userId);

        // Check if office location exists
        const location = await Location.findOne();
        if (!location) {
            return res.status(400).json({ status: false, message: "Office location not set" });
        }

        console.log("Office Location Found:", location);

        // Calculate distance between user and office
        console.log("User Location:", longitude, latitude);
        console.log("Office Location:", location.longitude, location.latitude);

        const distance = Math.sqrt(
            Math.pow(location.longitude - longitude, 2) +
            Math.pow(location.latitude - latitude, 2)
        ) * 111000;

        console.log("Calculated Distance:", distance);

        if (distance > 200) {
            return res.status(400).json({ status: false, message: `You are too far from the office. Distance: ${distance} meters` });
        }

        // Get the current date without time (YYYY-MM-DD)
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // Check if user already has a check-in for today
        const checkInRecord = await Attendance.findOne({
            userId,
            checkType: "check-in",
            timestamp: { $gte: today }
        });

        if (checkType === "check-out") {
            // If user tries to check-out without a prior check-in, block it
            if (!checkInRecord) {
                return res.status(400).json({
                    status: false,
                    message: "You must check-in first before checking out"
                });
            }

            // Check if user already checked out today
            const checkOutRecord = await Attendance.findOne({
                userId,
                checkType: "check-out",
                timestamp: { $gte: today }
            });

            if (checkOutRecord) {
                return res.status(400).json({
                    status: false,
                    message: `You have already checked out today at ${checkOutRecord.timestamp.toISOString()}`
                });
            }
        }

        // Save attendance record
        const attendance = new Attendance({ userId, longitude, latitude, checkType });
        await attendance.save();

        res.status(200).json({
            status: true,
            message: "Attendance recorded successfully",
            checkType: attendance.checkType,
            timestamp: attendance.timestamp.toISOString() // Store in ISO format
        });

        console.log("Attendance Recorded:", attendance);

    } catch (err) {
        console.error("Server Error:", err.message);
        res.status(500).json({ status: false, message: "Server error", error: err.message });
    }
});

  // Check-in/Check-out API
  app.post("/api/attendance", async (req, res) => {
    console.log("Headers Received:", req.headers);
    console.log("Received Request Body:", req.body); 

    try {
        const { longitude, latitude, checkType } = req.body;

        if (!longitude || !latitude || !checkType) {
            return res.status(400).json({
                status: false,
                message: "Longitude, latitude, and checkType are required",
            });
        }

        const authHeader = req.headers.authorization;

        // Validate token presence
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ status: false, message: "Invalid or missing Authorization header" });
        }

        // Extract and verify token
        const token = authHeader.split(" ")[1];
        console.log("Received Token:", token);

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
            console.log("Decoded Token:", decoded);
        } catch (err) {
            console.error("JWT Verification Error:", err.message);
            return res.status(401).json({ status: false, message: "Invalid User" });
        }

        if (!decoded || !decoded.userId) {
            return res.status(401).json({ status: false, message: "Invalid User structure" });
        }

        const userId = decoded.userId;
        console.log("User ID from Token:", userId);

        // Check if office location exists
        const location = await Location.findOne();
        if (!location) {
            return res.status(400).json({ status: false, message: "Office location not set" });
        }

        console.log("Office Location Found:", location);

        // Calculate distance between user and office
        console.log("User Location:", longitude, latitude);
        console.log("Office Location:", location.longitude, location.latitude);

        const distance = Math.sqrt(
            Math.pow(location.longitude - longitude, 2) +
            Math.pow(location.latitude - latitude, 2)
        ) * 111000;

        console.log("Calculated Distance:", distance);

        if (distance > 200) {
            return res.status(400).json({ status: false, message: `You are too far from the office. Distance: ${distance} meters` });
        }

        // Get the current date in UTC
        const today = new Date();
        today.setUTCHours(0, 0, 0, 0); // Reset time to start of the day (UTC)

        // Check if user is trying to check out before checking in
        if (checkType === "check-out") {
            const lastCheckIn = await Attendance.findOne({
                userId,
                checkType: "check-in",
                timestamp: { $gte: today } // Find today's check-in
            });

            if (!lastCheckIn) {
                return res.status(400).json({
                    status: false,
                    message: "You must check in first before checking out."
                });
            }
        }

        // Save attendance record with timestamp in UTC format
        const attendance = new Attendance({ 
            userId, 
            longitude, 
            latitude, 
            checkType, 
            timestamp: new Date().toISOString() // Store in UTC format
        });

        await attendance.save();

        console.log("Attendance Recorded:", attendance);

        res.status(200).json({
            status: true,
            message: "Attendance recorded successfully",
            checkType: attendance.checkType,
            timestamp: attendance.timestamp // Always UTC format
        });

    } catch (err) {
        console.error("Server Error:", err.message);
        res.status(500).json({ status: false, message: "Server error", error: err.message });
    }
});


// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

app.post("/api/generate-random-attendance", async (req, res) => {
    try {
        const { email } = req.body;
        const month = parseInt(req.headers["month"]); // Read month from headers
        const year = parseInt(req.headers["year"]);   // Read year from headers

        if (!email) {
            return res.status(200).json({ status: false, message: "Email is required" });
        }
        if (!month || month < 1 || month > 12) {
            return res.status(200).json({ status: false, message: "Invalid or missing month (1-12)" });
        }
        if (!year || year < 2000 || year > new Date().getFullYear()) {
            return res.status(200).json({ status: false, message: "Invalid or missing year" });
        }

        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(200).json({ status: false, message: "User not found" });
        }

        console.log("User Found:", user);

        const numberOfDays = 10; // Number of random days to generate
        const records = [];
        const workTimeRecords = []; // Store total work time per day

        for (let i = 0; i < numberOfDays; i++) {
            // Generate a random date in the specified month & year
            const randomDay = Math.floor(Math.random() * 28) + 1; // Avoid edge cases (28 to be safe)
            const randomDate = new Date(year, month - 1, randomDay);
            randomDate.setHours(Math.floor(Math.random() * 5) + 7); // Between 7 AM - 12 PM
            randomDate.setMinutes(Math.floor(Math.random() * 60));
            randomDate.setSeconds(0);

            // Create a check-in record
            const checkIn = new Attendance({
                userId: user._id,
                checkType: "check-in",
                longitude: 31.2357, // Mock location (Cairo example)
                latitude: 30.0444,
                timestamp: randomDate,
            });

            records.push(checkIn);
            let workTimeInHours = 0; // Initialize work time for the day

            // Random chance to add check-out (skip some days)
            if (Math.random() > 0.3) {  // 70% chance of having a check-out
                const checkOutTime = new Date(randomDate);
                checkOutTime.setHours(checkOutTime.getHours() + Math.floor(Math.random() * 5) + 4); // Add 4-8 hours

                const checkOut = new Attendance({
                    userId: user._id,
                    checkType: "check-out",
                    longitude: 31.2357, // Mock location (Cairo example)
                    latitude: 30.0444,
                    timestamp: checkOutTime,
                });

                records.push(checkOut);

                // Calculate total work time in hours
                workTimeInHours = (checkOutTime - randomDate) / (1000 * 60 * 60); // Convert ms to hours

                // Save total work time for this day
                workTimeRecords.push({
                    userId: user._id,
                    date: randomDate.toISOString().split("T")[0], // Save only the date
                    workTime: workTimeInHours.toFixed(2) // Save as string with 2 decimal places
                });
            }
        }

        // Save attendance records to MongoDB
        await Attendance.insertMany(records);

        // Save total work time records to a separate collection
        if (workTimeRecords.length > 0) {
            await WorkTime.insertMany(workTimeRecords);
        }

        res.status(200).json({
            status: true,
            message: "Random attendance data generated successfully",
            totalRecords: records.length,
            workTimeRecords: workTimeRecords,
            month: month,
            year: year
        });

    } catch (err) {
        console.error("Error generating random attendance:", err.message);
        res.status(200).json({ status: false, message: "Server error", error: err.message });
    }
});
