module.exports = {
  ensureAuthenticated: function (req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/auth/login");
  },

  ensureAdmin: function (req, res, next) {
    if (req.user && req.user.role === "admin") {
      return next();
    }
    res.redirect("/");
  },
};
