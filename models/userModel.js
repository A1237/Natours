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
    }
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

const User = mongoose.model('User', userSchema);

module.exports = User;