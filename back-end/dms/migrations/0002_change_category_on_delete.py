# Generated by Django 3.1.1 on 2020-09-10 15:10

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dms', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='document',
            name='category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.RESTRICT, to='dms.category'),
        ),
    ]
