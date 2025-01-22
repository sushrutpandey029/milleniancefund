import { DataTypes } from "sequelize";
import sequelize from "../Database/MySql_connection.js";

const Head = sequelize.define(
    "Dept_heads",
    {
        department: {
            type: DataTypes.ENUM(
                "Software Development",
                "Website Development",
                "E-commerce Development",
                "Mobile Development"
            ),
            allowNull: false,
        },
        dept_head_name: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        email: {
            type: DataTypes.STRING,
            allowNull: false,
            validate: {
                isEmail: true,
            },
        },
        phone: {
            type: DataTypes.STRING,
            allowNull: false,
            validate: {
                isNumeric: true,
                len: [10, 15], // Adjust for international numbers if needed
            },
        },
        designation: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        employes: {
            type: DataTypes.JSON, // JSON field to store multiple employee details
            allowNull: true,
        },
        password: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        normalpassword: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        refreshToken: {  // Add this field
            type: DataTypes.STRING,
            allowNull: true,
            defaultValue: 'accesstoken',
        }
    },
    {
        tableName: "Dept_heads",
        timestamps: true,
    }
);

export default Head;
