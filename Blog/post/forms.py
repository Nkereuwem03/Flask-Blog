from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, URLField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField
from flask_pagedown.fields import PageDownField
    
class CreatePostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired("Title required")])
    subtitle = StringField("Subtitle", validators=[DataRequired("Subtitle required")])
    # date = StringField("Publication date", default=present_time, render_kw={"readonly": True})
    body = PageDownField("What's on your mind?", validators=[DataRequired()])
    # body = CKEditorField("Blog Content", validators=[DataRequired("Content required")])
    # body = TextAreaField("Content", validators=[DataRequired()])
    img_url = URLField("Image URL", validators=[DataRequired("Url required"), URL()])
    submit = SubmitField("Submit")
    
class CommentForm(FlaskForm):
    body = CKEditorField(validators=[DataRequired("Content required")])
    submit = SubmitField("SUMMIT COMMENT")