import express from "express";

import {
    AdminRegister, Admin_login, AdminLogin, Admindashboard, AdminLogout,
    saveDeptHead, addhead, getDeptHeads,head_login,HeadLogin,headnewdashboard
} from '../Controller/Admin_Cntrl.js';


import { isAuthenticated } from '../Middlewares/isAuthenticated.js'; // Adjust path if necessary


const router = express.Router();

router.get('/', Admin_login);

router.get('/headlogin', head_login);
router.get('/headnewdashboard', headnewdashboard);

router.post('/login_head', HeadLogin);



router.post('/add_admin', AdminRegister);

router.post('/adminlogin', AdminLogin);

router.get('/dashboard', isAuthenticated, Admindashboard);
router.get('/logout', AdminLogout);

router.post('/saveDeptHead', saveDeptHead);
router.get('/addhead', addhead);
router.get('/getDeptHeads', getDeptHeads);





export default router;
