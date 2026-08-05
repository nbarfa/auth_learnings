from marshmallow import Schema, fields, validate, validates, ValidationError, validates_schema

class RegisterSchema(Schema):
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=20),
            validate.Regexp(r"^[A-Za-z0-9_]+$")
        ]
    )

    email = fields.Email(required=True)

    password = fields.Str(
        required=True,
        validate=[
            validate.Length(min=8),
            validate.Regexp(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$")
        ]
    )

    confirm_password = fields.Str(required=True)

    @validates("username")
    def validate_username(self, value):
        if value.lower() in ["admin", "root", "owner"]:
            raise ValidationError("Username admin, root, and owner are not allowed.")
        

    @validates_schema
    def validate_data(self,data, **kwargs):
        if data["password"] != data["confirm_password"]:
            raise ValidationError("Password and confirm password do not match.", field_name="confirm_password")


class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(
        required=True,
        validate=[
            validate.Length(min=8),
            validate.Regexp(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$")
        ]
    )