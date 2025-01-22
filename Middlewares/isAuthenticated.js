export const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
      return next(); // User is logged in, proceed to the requested page
    }
    return res.status(401).redirect('/'); // Redirect to login page if not authenticated
  };
  