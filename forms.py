
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")
    
class RegistrationForm(FlaskForm):
    name = StringField(label="Name", validators=[DataRequired()])
    email = StringField(label="Email", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Register")
    
class LoginForm(FlaskForm):
    email = StringField(label="Email")
    password = PasswordField(label="Password")
    submit = SubmitField(label="Login")

# Form to add comment to Blog posts
class CommentForm(FlaskForm):
    comment  = CKEditorField(label="What do you think of this Blog Post?", validators=[DataRequired()])
    submit = SubmitField(label='Submit Comment')