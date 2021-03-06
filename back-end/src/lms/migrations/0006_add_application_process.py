# Generated by Django 3.1.7 on 2021-04-17 13:15

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('lms', '0005_added_uniforms'),
    ]

    operations = [
        migrations.CreateModel(
            name='ApplicationProcess',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('medical_examination', models.CharField(blank=True, choices=[('FI', 'годен'), ('FMR', 'годен с незначительными ограничениями'), ('FLI', 'ограниченно годен'), ('UR', 'ограниченно не годен'), ('UN', 'не годен')], max_length=3)),
                ('prof_psy_selection', models.CharField(blank=True, choices=[('FI', 'I'), ('SE', 'II'), ('TH', 'III'), ('FO', 'IV')], max_length=2)),
                ('preferential_right', models.BooleanField(default=False)),
                ('characteristic_handed_over', models.BooleanField(default=False)),
                ('criminal_record_handed_over', models.BooleanField(default=False)),
                ('passport_handed_over', models.BooleanField(default=False)),
                ('registration_certificate_handed_over', models.BooleanField(default=False)),
                ('university_card_handed_over', models.BooleanField(default=False)),
                ('application_handed_over', models.BooleanField(default=False)),
            ],
            options={
                'verbose_name': 'Application Process',
                'verbose_name_plural': 'Application Processes',
            },
        ),
        migrations.AddField(
            model_name='student',
            name='application_process',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='lms.applicationprocess'),
        ),
    ]
