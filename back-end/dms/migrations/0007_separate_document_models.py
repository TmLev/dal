# Generated by Django 3.1.2 on 2020-10-12 13:12

import datetime
from django.db import migrations, models
import django.db.models.deletion
import taggit.managers


class Migration(migrations.Migration):

    dependencies = [
        ('taggit', '0003_taggeditem_add_unique_index'),
        ('dms', '0006_extract_auth_app'),
    ]

    operations = [
        migrations.CreateModel(
            name='ClassMaterial',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.TextField()),
                ('annotation', models.TextField(blank=True)),
                ('type', models.CharField(choices=[('LE', 'lectures'), ('SE', 'seminars'), ('GR', 'groups'), ('PR', 'practices')], max_length=2)),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dms.file')),
                ('topic', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dms.topic')),
            ],
            options={
                'verbose_name': 'Class Material',
                'verbose_name_plural': 'Class Materials',
            },
        ),
        migrations.CreateModel(
            name='Paper',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.TextField()),
                ('annotation', models.TextField(blank=True)),
                ('publication_date', models.DateField(default=datetime.date.today)),
                ('authors', models.ManyToManyField(blank=True, to='dms.Author')),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dms.category')),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dms.file')),
                ('publishers', models.ManyToManyField(blank=True, to='dms.Publisher')),
                ('tags', taggit.managers.TaggableManager(blank=True, help_text='A comma-separated list of tags.', through='taggit.TaggedItem', to='taggit.Tag', verbose_name='Tags')),
            ],
            options={
                'verbose_name': 'Paper',
                'verbose_name_plural': 'Papers',
            },
        ),
        migrations.DeleteModel(
            name='Document',
        ),
    ]
