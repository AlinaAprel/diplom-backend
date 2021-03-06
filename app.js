require('dotenv').config();

const express = require('express');
const { celebrate, Joi, errors } = require('celebrate');

const whitelist = [
  'http://localhost:8080',
  'https://yandex.diplom.students.nomoreparties.space',
];
const corsOptions = {
  origin: function (origin, callback) {
    if (whitelist.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200,
};

const PORT = 3000;
const app = express();
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const { createUser, login } = require('./controllers/users');
const auth = require('./middlewares/auth');
const { requestLogger, errorLogger } = require('./middlewares/logger');

app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect('mongodb://localhost:27017/newsdiplom', {
  useNewUrlParser: true,
  useCreateIndex: true,
  useFindAndModify: false,
  useUnifiedTopology: true,
});

app.use(requestLogger);

app.get('/crash-test', () => {
  setTimeout(() => {
    throw new Error('Сервер сейчас упадёт');
  }, 0);
});

app.post('/signin', celebrate({
  body: Joi.object().keys({
    email: Joi.string().required().email(),
    password: Joi.string().required().pattern(/\S+/),
  }),
}), login);

app.post('/signup', celebrate({
  body: Joi.object().keys({
    name: Joi.string().required().min(2).max(30),
    email: Joi.string().required().email(),
    password: Joi.string().required().pattern(/\S+/),
  }),
}), createUser);

app.use(auth);

app.use('/articles', require('./routes/article'));
app.use('/users/me', require('./routes/user'));

app.use(errorLogger);
app.use(errors());

app.use((err, req, res, next) => {
  if (err.statusCode === undefined) {
    next(err);
    res.status(500).send({ message: `На сервере произошла ошибка ${err}` });
  } else {
    res.status(err.statusCode).send({ message: err.message });
  }
});

app.listen(PORT);

app.use('/', (req, res) => {
  res.status(404).send({ message: 'Запрашиваемый ресурс не найден' });
});
