# Generated by Django 3.1.5 on 2021-03-18 14:52

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import dms.models.books
import dms.models.common
import dms.models.documents
import taggit.managers
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('common', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('taggit', '0003_taggeditem_add_unique_index'),
    ]

    operations = [
        migrations.CreateModel(
            name='Author',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('surname', models.CharField(max_length=32)),
                ('name', models.CharField(max_length=32)),
                ('patronymic', models.CharField(blank=True, max_length=32)),
                ('citizenship', models.CharField(max_length=64, null=True)),
                ('permanent_address', models.CharField(max_length=128, null=True)),
                ('birth_info', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='common.birthinfo')),
                ('contact_info', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='common.contactinfo')),
            ],
            options={
                'verbose_name': 'Author',
                'verbose_name_plural': 'Authors',
            },
        ),
        migrations.CreateModel(
            name='Book',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.TextField(blank=True)),
                ('annotation', models.TextField(blank=True)),
                ('upload_date', models.DateField(default=datetime.date.today)),
                ('publication_year', models.PositiveSmallIntegerField(default=dms.models.books.current_year)),
                ('page_count', models.PositiveSmallIntegerField(default=None, null=True)),
                ('authors', models.ManyToManyField(blank=True, to='dms.Author')),
            ],
            options={
                'verbose_name': 'Book',
                'verbose_name_plural': 'Books',
            },
        ),
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
            ],
            options={
                'verbose_name': 'Category',
                'verbose_name_plural': 'Categories',
            },
        ),
        migrations.CreateModel(
            name='Cover',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('image', models.ImageField(blank=True, upload_to=dms.models.books.upload_to)),
            ],
            options={
                'verbose_name': 'Cover',
                'verbose_name_plural': 'Covers',
            },
        ),
        migrations.CreateModel(
            name='File',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('content', models.FileField(blank=True, upload_to=dms.models.documents.upload_to)),
                ('name', models.CharField(max_length=255)),
            ],
            options={
                'verbose_name': 'File',
                'verbose_name_plural': 'Files',
            },
        ),
        migrations.CreateModel(
            name='Publisher',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
            ],
            options={
                'verbose_name': 'Publisher',
                'verbose_name_plural': 'Publishers',
            },
        ),
        migrations.CreateModel(
            name='Section',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order', models.PositiveIntegerField(db_index=True, editable=False, verbose_name='order')),
                ('title', models.CharField(max_length=255)),
                ('subject', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sections', to='common.subject')),
            ],
            options={
                'verbose_name': 'Section',
                'verbose_name_plural': 'Sections',
                'ordering': ('order',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Topic',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order', models.PositiveIntegerField(db_index=True, editable=False, verbose_name='order')),
                ('title', models.CharField(max_length=255)),
                ('annotation', models.TextField(blank=True)),
                ('section', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='topics', to='dms.section')),
            ],
            options={
                'verbose_name': 'Topic',
                'verbose_name_plural': 'Topics',
                'ordering': ('order',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Paper',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.TextField(blank=True)),
                ('annotation', models.TextField(blank=True)),
                ('upload_date', models.DateField(default=datetime.date.today)),
                ('publication_date', models.DateField(default=datetime.date.today)),
                ('authors', models.ManyToManyField(blank=True, to='dms.Author')),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.RESTRICT, to='dms.category')),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dms.file')),
                ('publishers', models.ManyToManyField(blank=True, to='dms.Publisher')),
                ('tags', taggit.managers.TaggableManager(blank=True, help_text='A comma-separated list of tags.', through='taggit.TaggedItem', to='taggit.Tag', verbose_name='Tags')),
                ('user', models.ForeignKey(default=dms.models.common.super_user_id, on_delete=django.db.models.deletion.SET_DEFAULT, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Paper',
                'verbose_name_plural': 'Papers',
            },
        ),
        migrations.CreateModel(
            name='FavoriteBook',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('book', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dms.book')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Favorite book',
                'verbose_name_plural': 'Favorite books',
            },
        ),
        migrations.CreateModel(
            name='ClassMaterial',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.TextField(blank=True)),
                ('annotation', models.TextField(blank=True)),
                ('upload_date', models.DateField(default=datetime.date.today)),
                ('type', models.CharField(choices=[('LE', 'lectures'), ('SE', 'seminars'), ('GR', 'groups'), ('PR', 'practices')], max_length=2)),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dms.file')),
                ('topic', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='class_materials', to='dms.topic')),
                ('user', models.ForeignKey(default=dms.models.common.super_user_id, on_delete=django.db.models.deletion.SET_DEFAULT, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Class Material',
                'verbose_name_plural': 'Class Materials',
            },
        ),
        migrations.AddField(
            model_name='book',
            name='cover',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, to='dms.cover'),
        ),
        migrations.AddField(
            model_name='book',
            name='file',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dms.file'),
        ),
        migrations.AddField(
            model_name='book',
            name='publishers',
            field=models.ManyToManyField(blank=True, to='dms.Publisher'),
        ),
        migrations.AddField(
            model_name='book',
            name='subjects',
            field=models.ManyToManyField(blank=True, to='common.Subject'),
        ),
        migrations.AddField(
            model_name='book',
            name='user',
            field=models.ForeignKey(default=dms.models.common.super_user_id, on_delete=django.db.models.deletion.SET_DEFAULT, to=settings.AUTH_USER_MODEL),
        ),
    ]
