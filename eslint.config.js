<<<<<<< Updated upstream
const security = require("eslint-plugin-security");

module.exports = [
  {
    ignores: [
      "node_modules/**",
      "vendor/**",
      "dist/**",
      "build/**",
      "**/*.min.js"
    ],

    files: ["**/*.js"],

    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
    },

    plugins: {
      security,
    },

    rules: {
      ...security.configs.recommended.rules,
    },
  },
];
=======
const security = require("eslint-plugin-security");

module.exports = [
  {
    ignores: [
      "node_modules/**",
      "vendor/**",
      "dist/**",
      "build/**",
      "**/*.min.js"
    ],

    files: ["**/*.js"],

    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
    },

    plugins: {
      security,
    },

    rules: {
      ...security.configs.recommended.rules,
    },
  },
];
>>>>>>> Stashed changes
