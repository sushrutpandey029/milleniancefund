import { DataTypes } from "sequelize";

import sequelize from "../Database/MySql_connection.js";

const admin = sequelize.define('admin',{
    Admin_name:{
        type:DataTypes.STRING,
        allowNull:false,
    },
    Email_id:{
        type:DataTypes.STRING,
        allowNull:false,
    },
    Password :{
        type:DataTypes.STRING,
        allowNull: false
    },
    refreshToken: {  // Add this field
        type: DataTypes.STRING,
        allowNull: true,
        defaultValue: 'accesstoken',
    }
},{
    tableName: 'admins',
    timestamps: true,
})

export default admin;