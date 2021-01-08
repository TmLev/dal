# Generated by Django 3.1.3 on 2020-12-04 14:07

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Session',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=10)),
                ('chat_id', models.PositiveBigIntegerField(null=True)),
            ],
            options={
                'verbose_name': 'Telegram Bot Auth Session',
                'verbose_name_plural': 'Telegram Bot Auth Sessions',
            },
        ),
    ]