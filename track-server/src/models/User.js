const mongoose = require("mongoose");
const bcyrpt = require("bcrypt");

const userSchema = new mongoose.Schema({
	email: {
		type: String,
		required: true,
		unique: true,
	},
	password: {
		type: String,
		required: true,
	},
});

userSchema.pre("save", function (next) {
	const user = this;

	if (!user.isModified("password")) {
		return next();
	}

	bcyrpt.genSalt(10, (err, salt) => {
		if (err) {
			return next(err);
		}
		bcyrpt.hash(user.password, salt, (err, hash) => {
			if (err) {
				return next(err);
			}
			user.password = hash;
			next();
		});
	});
});

userSchema.methods.comparePassword = function (candidatePassword) {
	const user = this;

	return new Promise((resolve, reject) => {
		bcyrpt.compare(candidatePassword, user.password, (err, isMatch) => {
			if (err) {
				return reject(err);
			}

			if (!isMatch) {
				return reject(false);
			}

			resolve(true);
		});
	});
};

mongoose.model("User", userSchema);
