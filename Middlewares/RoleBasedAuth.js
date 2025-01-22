export const authorizeRole = (allowedRoles) => {
    return (req, res, next) => {
        // Check if the user's role in session matches the allowed roles
        if (req.session.user && allowedRoles.includes(req.session.user.role)) {
            next(); // Proceed if the role matches
        } else {
            return res.status(403).send({
                message: "Access denied. You do not have the required permissions."
            });
        }
    };
};