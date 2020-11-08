# Generated by Django 3.1.2 on 2020-11-08 14:25

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('lms', '0005_auto_20201002_1334'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='lesson',
            name='course',
        ),
        migrations.RemoveField(
            model_name='lesson',
            name='lesson_type',
        ),
        migrations.RemoveField(
            model_name='lesson',
            name='place',
        ),
        migrations.RemoveField(
            model_name='lesson',
            name='teacher',
        ),
        migrations.AlterUniqueTogether(
            name='lessonmilgroup',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='lessonmilgroup',
            name='lesson',
        ),
        migrations.RemoveField(
            model_name='lessonmilgroup',
            name='milgroup',
        ),
        migrations.RemoveField(
            model_name='mark',
            name='control_form',
        ),
        migrations.RemoveField(
            model_name='mark',
            name='lesson',
        ),
        migrations.RemoveField(
            model_name='mark',
            name='student',
        ),
        migrations.AlterUniqueTogether(
            name='studentskill',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='studentskill',
            name='skill',
        ),
        migrations.RemoveField(
            model_name='studentskill',
            name='student',
        ),
        migrations.AlterUniqueTogether(
            name='studentstudentpost',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='studentstudentpost',
            name='student',
        ),
        migrations.RemoveField(
            model_name='studentstudentpost',
            name='student_post',
        ),
        migrations.DeleteModel(
            name='Activity',
        ),
        migrations.DeleteModel(
            name='ActivityType',
        ),
        migrations.DeleteModel(
            name='ControlForm',
        ),
        migrations.DeleteModel(
            name='Course',
        ),
        migrations.DeleteModel(
            name='Lesson',
        ),
        migrations.DeleteModel(
            name='LessonMilgroup',
        ),
        migrations.DeleteModel(
            name='LessonType',
        ),
        migrations.DeleteModel(
            name='Mark',
        ),
        migrations.DeleteModel(
            name='Place',
        ),
        migrations.DeleteModel(
            name='Skill',
        ),
        migrations.DeleteModel(
            name='StudentPost',
        ),
        migrations.DeleteModel(
            name='StudentSkill',
        ),
        migrations.DeleteModel(
            name='StudentStudentpost',
        ),
    ]