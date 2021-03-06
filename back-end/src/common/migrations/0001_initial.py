# Generated by Django 3.1.7 on 2021-03-26 11:44

import common.models.persons
from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='BirthInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField()),
                ('country', models.CharField(max_length=32, null=True)),
                ('city', models.CharField(max_length=32, null=True)),
            ],
            options={
                'verbose_name': 'Birth Info',
                'verbose_name_plural': 'Birth Infos',
            },
        ),
        migrations.CreateModel(
            name='ContactInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('corporate_email', models.EmailField(blank=True, max_length=254, null=True)),
                ('personal_email', models.EmailField(blank=True, max_length=254, null=True)),
                ('personal_phone_number', models.CharField(blank=True, max_length=32, null=True)),
            ],
            options={
                'verbose_name': 'Contact Info',
                'verbose_name_plural': 'Contact Infos',
            },
        ),
        migrations.CreateModel(
            name='Photo',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('image', models.ImageField(blank=True, upload_to=common.models.persons.upload_to)),
            ],
            options={
                'verbose_name': 'PersonPhoto',
                'verbose_name_plural': 'PersonPhoto',
            },
        ),
        migrations.CreateModel(
            name='Relative',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('surname', models.CharField(max_length=32)),
                ('name', models.CharField(max_length=32)),
                ('patronymic', models.CharField(blank=True, max_length=32)),
                ('citizenship', models.CharField(blank=True, max_length=64)),
                ('permanent_address', models.CharField(blank=True, max_length=128)),
                ('type', models.CharField(choices=[('FA', 'отец'), ('MO', 'мать'), ('BR', 'брат'), ('SI', 'сестра')], max_length=2)),
            ],
            options={
                'verbose_name': 'Relative',
                'verbose_name_plural': 'Relatives',
            },
        ),
        migrations.CreateModel(
            name='Subject',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('annotation', models.TextField(blank=True)),
            ],
            options={
                'verbose_name': 'Subject',
                'verbose_name_plural': 'Subjects',
            },
        ),
    ]
