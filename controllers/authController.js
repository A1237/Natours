const {
  promisify
} = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const AppError = require('./../utils/appError');

const signToken = id => {
  return jwt.sign({
      id
    },
    process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN
    }
  );
};

exports.signup = async (req, res, next) => {
  try {
    const newUser = await User.create({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm,
      passwordChangedAt: req.body.passwordChangedAt
    });

    // console.log(newUser);

    const token = signToken(newUser._id);

    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: newUser
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'Fail',
      message: err
    });
  }
};

exports.login = async (req, res, next) => {
  try {
    const {
      email,
      password
    } = req.body;

    //1)check if the email and password exits
    if (!email || !password) {
      return next(new AppError('please provide email and password', 400));
    }
    //2)check if the user && pasword is correct(if its is exits in the DATABASE)
    const user = await User.findOne({
      email
    }).select('+password');

    console.log(user);

    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError('Incorrect email or password', 401));
    }
    //3) If Everything OK ,send Token
    const token = signToken(user._id);
    res.status(200).json({
      status: 'success',
      token
    });
  } catch (err) {
    res.status(404).json({
      status: 'Fail'
    });
  }
};

exports.protect = async (req, res, next) => {
  try {
    let token;
    // 1) Getting token and check if it's there
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }


    if (!token) {
      return next(
        new AppError('You are not logged in! Please log in to get access.', 401)
      );
    }
    // 2) Verification Token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    console.log(decoded);
    // 3)Check if user still exists
    const currentUser = await User.findById(decoded.id)
    if (!currentUser) {
      return next(new AppError('The User belonging to this token does no longer exist.', 401))
    }
    // 4)Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(new AppError('User Recently changed Password! Please log in again', 401))
    }

    // Grant Access To Protected Route
    req.user = currentUser
    next();
  } catch (err) {
    console.log(err)
  }


};

//*  not Yet Working

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.roles)) {
      return next(new AppError('You do not have permission to perform this action'))
    }
    next()
  }

}
//*  not Yet Working

exports.forgotPassword = async (req, res, next) => {
  try {
    // 1) Get User Based on Posted Email
    const user = await User.findOne({
      email: req.body.email
    })

    if (!user) {
      next(new AppError('There is no user with email address', 404))
    }
    // 2)Generate the random reset Token
    const resetToken = user.createPasswordResetToken();
    console.log(resetToken)
    await user.save({
      validateBeforeSave: false
    })
    //3)Send it TO user's email
  } catch (err) {
    console.log(err);
  }

}

exports.resetPassword = (req, res, next) => {

}