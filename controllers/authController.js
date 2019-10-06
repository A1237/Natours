const {
  promisify
} = require('util')
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const AppError = require('./../utils/appError');

const signToken = (id) => {
  return jwt.sign({
      id
    },
    process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN
    }
  );
}

exports.signup = async (req, res, next) => {
  try {
    const newUser = await User.create({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm
    });

    // console.log(newUser);

    const token = signToken(newUser._id)

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
      return next(new AppError('Incorrect email or password', 401))
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
  let token;
  // 1) Getting token and check if it's there
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }
  console.log(token);

  if (!token) {
    return next(new AppError('You are not logged in! Please log in to get access.', 401))
  }
  // 2) Verification Token
  const decoded = await promisify(jwt.verify(token, process.env.JWT_SECRET));
  console.log(decoded)
  // 3)Check if user still exists

  // 4)Check if user changed password after the token was issued

  next();
}