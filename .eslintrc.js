module.exports = {
  env: {
    es2021: true,
    es6: true,
    node: true,
  },
  extends: 'airbnb-base',
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module',
  },
  rules: {
    'no-underscore-dangle': ['off', { allow: ['_id'] }],
    'no-console': 'off',
    'no-unused-vars': 'off',
  },
};