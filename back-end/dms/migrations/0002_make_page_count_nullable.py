# Generated by Django 3.1.5 on 2021-01-29 11:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dms', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='book',
            name='page_count',
            field=models.PositiveSmallIntegerField(default=None, null=True),
        ),
    ]
