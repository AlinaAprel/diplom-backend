const Article = require('../models/article');

const BadRequestError = require('../errors/bad-request-err');
const NotFoundError = require('../errors/not-found-err');
const UnauthorizedError = require('../errors/unauthorized-err');
const ForbiddenError = require('../errors/forbidden-err');

module.exports.getArticles = (req, res, next) => {
  Article.find({ owner: req.user._id })
    .then((user) => {
      if (!user) {
        throw new NotFoundError({ message: 'У вас нет сохраненных фотографий' });
      }
      res.send({ data: user });
    })
    .catch((err) => next(err));
};

module.exports.createArticle = (req, res, next) => {
  const {
    keyword, title, text, date, source, link, image,
  } = req.body;
  const owner = req.user._id;
  Article.create({
    keyword, title, text, date, source, link, image, owner,
  })
    .then(() => {
      res.send({
        data: keyword, title, text, date, source, link, image,
      });
    })
    .catch((err) => {
      if (err.name === 'ValidationError') {
        throw new UnauthorizedError(`Переданы некорректные данные ${err}`);
      }
      next(err);
    })
    .catch((err) => next(err));
};

module.exports.deleteArticle = (req, res, next) => {
  const articleOwner = req.user._id;
  const articleId = req.params._id;
  Article.findById(req.params.articleId).select('+owner')
    .orFail(new NotFoundError('Карточка не найдена'))
    .then((article) => {
      if (articleOwner !== article.owner.toString()) {
        throw new ForbiddenError('Вы не можете удалять чужие карточки!');
      }
      Article.deleteOne(articleId)
        .then(() => res.send({ message: 'Карточка удалена!' }));
    })
    .catch((err) => {
      if (err.name === 'NotFoundError') {
        throw new NotFoundError('Карточка не найдена');
      }
      if (err.name === 'CastError') {
        throw new BadRequestError('Переданы неверные данные');
      }
      next(err);
    })
    .catch((err) => next(err));
};
