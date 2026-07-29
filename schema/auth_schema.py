from marshmallow import Schema, fields, validate

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

