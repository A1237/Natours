const crypto = require('crypto')
const mongoose = require('mongoose');
const validator = require('validator')
const bcrpyt = require('bcryptjs');

const {
    Schema
} = mongoose;

const userSchema = new Schema({
    name: {
        type: String,
        trim: true,
        required: [true, 'Please Tell us your name'],

    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    photo: String,
    role: {
        type: String,
        enum: ['user', 'guide', 'lead-guide', 'admin'],
        default: 'user'
    },
    password: {
        type: String,
        required: [true, 'Please Provide a Password'],
        minlength: 8,
        select: false
    },
    passwordConfirm: {
        type: String,
        required: [true, 'Please Confirm your Password'],
        validate: {
            validator: function (el) {
                return el === this.password
            },
            message: 'Passwords are not Same'
        }
    },
    passwordChangedAt: {
        type: Date,
        select: true
    },
    passwordResetToken: String,
    passwordResetExpires: Date
});

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    this.password = await bcrpyt.hash(this.password, 12);

    this.passwordConfirm = undefined;

    next()
})

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
    return await bcrpyt.compare(candidatePassword, userPassword)
}

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimeStamp = (this.passwordChangedAt.getTime() / 1000) * 1;
        console.log(changedTimeStamp, JWTTimestamp);
        return JWTTimestamp < changedTimeStamp
    }
    // flase means not true
    return false

}

userSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex');

    this.passwordResetToken = crypto.createHash('sha258').update(resetToken).digest('hex')

    console.log({
        resetToken
    }, this.passwordResetToken)

    this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

    return resetToken;
}

const User = mongoose.model('User', userSchema);

module.exports = User;