<template>
  <div :class="$style.root">
    <template v-if="!formSubmitted">
      <div :class="$style.header">
        <h2 :class="$style.title">
          {{ headers[step] }}
        </h2>

        <el-steps
          :active="stepIndex"
          finish-status="success"
          :align-center="true"
        >
          <el-step
            v-for="(title, key) in STEPS_RU"
            :key="key"
            @click.native="goToStep(key)"
          />
        </el-steps>
      </div>

      <template v-if="step !== STEPS.brothers && step !== STEPS.sisters">
        <el-form
          ref="form"
          :key="step"
          :model="studentData[step]"
          :rules="rules[step]"
        >
          <el-form-item
            v-for="({ component, title, props = {} }, key) in fields[step]"
            :key="key"
            :prop="key"
          >
            <component
              :is="component"
              v-model="studentData[step][key]"
              :title="title"
              v-bind="props"
            />
          </el-form-item>
        </el-form>

        <div
          v-if="
            step === STEPS.photo &&
              studentData.photo.photo &&
              studentData.photo.photo.length
          "
          :style="{
            flex: 1,
            background: 'no-repeat center / contain',
            backgroundImage: `url('${getObjUrl(
              studentData.photo.photo[0].raw,
            )}')`,
            margin: '10px',
          }"
        />
      </template>

      <template v-else>
        <div>
          <el-button
            style="width: 100%"
            icon="el-icon-plus"
            type="primary"
            :style="{ sdhbchbsc: 3 }"
            @click="addTab"
          >
            Добавить {{ tabButtonLabel[step] }}
          </el-button>

          <el-tabs
            v-model="tabsIndex[step]"
            type="card"
            closable
            @tab-remove="removeTab"
          >
            <el-tab-pane
              v-for="(item, index) in studentData[step]"
              :key="index"
              :label="item.name || `${tabsLabel[step]} ${index + 1}`"
              :name="`${index}`"
            >
              <el-form
                v-if="+tabsIndex[step] === index"
                ref="form"
                :model="item"
                :rules="rules[step]"
              >
                <el-form-item
                  v-for="({ component, title, props = {} }, key) in fields[
                    step
                  ]"
                  :key="key"
                  :prop="key"
                >
                  <component
                    :is="component"
                    v-model="item[key]"
                    :title="title"
                    v-bind="props"
                  />
                </el-form-item>
              </el-form>
            </el-tab-pane>
          </el-tabs>
        </div>

        <div v-if="!studentData[step].length">
          Добавьте {{ tabsLabelMany[step] }} (при наличии)
        </div>
      </template>

      <div>
        <el-button v-if="step !== firstStep" @click="prev">
          Назад
        </el-button>

        <el-button
          v-if="step !== lastStep"
          type="primary"
          native-type="submit"
          @click="next"
        >
          Дальше
        </el-button>
        <el-button
          v-else
          v-loading="isSubmitting"
          type="primary"
          native-type="submit"
          @click="submit"
        >
          Отправить форму
        </el-button>
      </div>

      <div :class="$style.footer">
        <p :class="$style.footerText">
          При возникновении технических трудностей обращайтесь по адресу
          <a href="mailto:dal.mec.hse@gmail.com">dal.mec.hse@gmail.com</a>. В
          письме подробно опишите ситуацию и проблему, с которой Вы столкнулись.
        </p>
      </div>
    </template>

    <template v-else>
      <div :class="$style.thanks">
        <h2>Форма успешно отправлена</h2>
      </div>
    </template>
  </div>
</template>

<script>
import _pick from "lodash/pick";
import _omit from "lodash/omit";

import {
  DateInput,
  FileInput,
  TextInput,
  SelectInput,
  SingleCheckbox,
} from "@/common/inputs";
import allowMobileView from "@/utils/allowMobileView";
import { postStudent } from "@/api/students";

import {
  ABOUT,
  BIRTH_INFO,
  CONTACT_INFO,
  PASSPORT,
  RECRUITMENT_OFFICE,
  UNIVERSITY_INFO,
  MILSPECIALTY,
  PHOTO,
  AGREEMENT,
  HEADERS_BY_STEPS,
  STEPS_RU,
  getRelationData,
  STEPS,
} from "@/constants/applicantForm";

import { getReferenceMilSpecialties } from "@/api/reference-book";
import copyToClipboard from "@/utils/copyToClipboard";

export default {
  name: "ApplicantForm",
  components: {
    DateInput,
    FileInput,
    TextInput,
    SelectInput,
    SingleCheckbox,
  },

  data() {
    const createData = fields => Object.keys(fields).reduce(
      (memo, item) => ({
        ...memo,
        [item]: "",
      }),
      {},
    );

    return {
      studentData: __DEV__ && "fill" in this.$route.query
        // eslint-disable-next-line global-require
        ? require("@/constants/applicantForm").devInitData
        : {
          about: createData(ABOUT),
          birthInfo: createData(BIRTH_INFO),
          passport: createData(PASSPORT),
          recruitmentOffice: createData(RECRUITMENT_OFFICE),
          universityInfo: createData(UNIVERSITY_INFO),
          contactInfo: createData(CONTACT_INFO),
          mother: createData(getRelationData("матери")),
          father: createData(getRelationData("отца")),
          brothers: [],
          sisters: [],
          photo: { photo: null },
          milspecialty: createData(MILSPECIALTY),
          agreement: createData(AGREEMENT),
        },
      fields: {
        about: ABOUT,
        birthInfo: BIRTH_INFO,
        passport: PASSPORT,
        recruitmentOffice: RECRUITMENT_OFFICE,
        universityInfo: UNIVERSITY_INFO,
        contactInfo: CONTACT_INFO,
        mother: getRelationData("матери"),
        father: getRelationData("отца"),
        brothers: getRelationData("брата"),
        sisters: getRelationData("сестры"),
        photo: PHOTO,
        milspecialty: MILSPECIALTY,
        agreement: AGREEMENT,
      },

      formSubmitted: false,
      isSubmitting: false,
      headers: HEADERS_BY_STEPS,

      step: STEPS.about,
      STEPS,
      STEPS_RU,

      tabsIndex: {
        brothers: "",
        sisters: "",
      },

      tabsLabel: { brothers: "Брат", sisters: "Сестра" },
      tabsLabelMany: { brothers: "братьев", sisters: "сестёр" },
      tabButtonLabel: { brothers: "брата", sisters: "сестру" },
      relationsLabel: { brothers: "брата", sisters: "сёстры" },
    };
  },

  computed: {
    firstStep() {
      return Object.keys(STEPS)[0];
    },
    lastStep() {
      const stepsNames = Object.keys(STEPS);
      return stepsNames[stepsNames.length - 1];
    },
    stepIndex() {
      return Object.keys(STEPS).indexOf(this.step);
    },
    campus() {
      return this.studentData.universityInfo.campus;
    },
    rules() {
      const required = { required: true, message: "Обязательное поле" };
      const requiredBool = {
        required: true,
        message: "Обязательное поле",
        validator: (rule, value, cb) => {
          if (!value) {
            cb(new Error("Обязательное поле"));
          } else {
            cb();
          }
        },
      };

      const getValidator = (regExp, msg) => ({
        validator: (rule, value, cb) => {
          if (value && !regExp.test(value)) {
            cb(new Error(msg));
          } else {
            cb();
          }
        },
      });

      const getMaxLengthValidator = max => ({
        max,
        message: `Максимальное количество символов - ${max}`,
      });

      const mailValidator = getValidator(/@.+\..+/, "Введите корректную почту");
      const corpMailValidator = getValidator(
        /[A-Za-z0-9._%+-]+@edu\.hse\.ru$/,
        "Почта должна оканчиваться на @edu.hse.ru",
      );
      const phoneValidator = getValidator(
        /^\+?\d{11}$/,
        "Введите корректный номер телефона",
      );
      const makeRequired = fields => fields.reduce((memo, item) => ({
        ...memo,
        [item]: [required],
      }), {});

      const relationFields = {
        ...makeRequired([
          "surname",
          "name",
          "citizenship",
          "permanent_address",
          "date",
        ]),
        city: [required, getMaxLengthValidator(64)],
        country: [required, getMaxLengthValidator(64)],
        personal_email: [mailValidator],
        personal_phone_number: [phoneValidator],
      };

      const withMotherRules = Object.values(this.studentData.mother).filter(
        Boolean,
      ).length;

      const withFaterRules = Object.values(this.studentData.father).filter(
        Boolean,
      ).length;

      const motherFatherPhone = [
        {
          required: true,
          message: withFaterRules
            ? "Укажите номер матери или отца"
            : "Укажите номер матери",
        },
        phoneValidator,
      ];

      let fatherFields = {};

      if (!withMotherRules) {
        if (withFaterRules) {
          fatherFields = {
            ...relationFields,
            personal_phone_number: motherFatherPhone,
          };
        }
      } else if (!this.studentData.mother.personal_phone_number) {
        if (withFaterRules) {
          fatherFields = {
            ...relationFields,
            personal_phone_number: motherFatherPhone,
          };
        } else {
          fatherFields = {
            personal_phone_number: motherFatherPhone,
          };
        }
      }

      return {
        about: makeRequired([
          "surname",
          "name",
          "citizenship",
          "surname_genitive",
          "name_genitive",
        ]),
        birthInfo: {
          ...makeRequired(["date"]),
          country: [required, getMaxLengthValidator(64)],
          city: [required, getMaxLengthValidator(64)],
        },
        passport: {
          ...makeRequired(["ufms_name", "issue_date"]),
          series: [
            required,
            getValidator(/^\d{4}$/, "Введите серию паспорта в формате 1234"),
          ],
          code: [
            required,
            getValidator(/^\d{6}$/, "Введите номер паспорта в формате 567890"),
          ],
          ufms_code: [
            required,
            getValidator(
              /^\d{3}-\d{3}$/,
              "Введите код подразделения в формате 700-007 ",
            ),
          ],
        },
        recruitmentOffice: makeRequired(["title"]),
        universityInfo: {
          ...makeRequired(["campus", "card_id", "program", "group"]),
          program: [
            required,
            getValidator(
              /^\d\d(\.\d\d){2}$/,
              "Введите код программы в формате 01.02.03",
            ),
          ],
        },
        contactInfo: {
          personal_email: [mailValidator],
          corporate_email: [required, corpMailValidator],
          personal_phone_number: [phoneValidator],
        },
        mother: withMotherRules ? relationFields : {},
        father: fatherFields,
        brothers: relationFields,
        sisters: relationFields,
        photo: { photo: [required] },
        milspecialty: { milspecialty: [required] },
        agreement: { agreement: [requiredBool], isDataCorrect: [requiredBool] },
      };
    },
  },

  watch: {
    async step(nextValue) {
      window.scrollTo({
        left: 0,
        top: 0,
      });

      if (nextValue === STEPS.milspecialty) {
        try {
          const { data } = await getReferenceMilSpecialties(
            this.studentData.universityInfo.campus,
          );
          this.fillMilspecialtyOptions(data);
        } catch (e) {
          this.$message({
            type: "error",
            duration: 1000 * 5,
            message:
              "Ошибка загрузки данных. Вернитесь к предыдущему шагу и заново перейдите на текущий шаг",
          });
        }
      }
    },
  },

  created() {
    allowMobileView(true);
  },

  destroyed() {
    allowMobileView(false);
  },

  methods: {
    goToStep(key) {
      if (this.$route.hash === "#activate-god-mode") {
        this.step = key;
      }
    },

    fillMilspecialtyOptions(data) {
      this.fields.milspecialty.milspecialty.props.options = data.map(
        item => ({
          label: item.milspecialty
            ? `${item.code} - ${item.milspecialty}`
            : item.code,
          value: item.code,
        }),
      );
    },

    convertFamily(data) {
      return {
        surname: data.surname,
        name: data.name,
        patronymic: data.patronymic,
        citizenship: data.citizenship,
        permanent_address: data.permanent_address,
        contact_info: {
          personal_email: data.personal_email,
          personal_phone_number: data.personal_phone_number,
        },
        birth_info: {
          date: data.date,
          country: data.country,
          city: data.city,
        },
      };
    },

    validate() {
      let isValid = true;
      const ref = this.$refs.form;

      const formValidate = valid => {
        if (!valid && isValid) {
          this.$message({
            type: "error",
            message: "Заполните все обязательные поля",
          });
          isValid = false;
        }
      };

      if (ref) {
        if (this.lodash.isArray(ref)) {
          ref.forEach(item => item.validate(formValidate));
        } else {
          ref.validate(formValidate);
        }
      }

      return isValid;
    },

    next() {
      const { studentData, step } = this;
      const data = studentData[step];

      Object.keys(data).forEach(key => {
        if (this.lodash.isString(data[key])) {
          data[key] = data[key].trim();
        }
      });

      if (this.validate()) {
        const stepsKeys = Object.keys(STEPS);
        const stepIndex = stepsKeys.indexOf(step);
        this.step = stepsKeys[stepIndex + 1] || stepsKeys[stepsKeys.length - 1];
      }
    },

    prev() {
      const stepsKeys = Object.keys(STEPS);
      const stepIndex = stepsKeys.indexOf(this.step);
      const newIndex = stepIndex >= 1 ? stepIndex - 1 : 0;
      this.step = stepsKeys[newIndex];
    },

    addTab() {
      const { step } = this;

      if (this.validate()) {
        this.studentData[step] = [
          ...this.studentData[step],
          Object.keys(getRelationData(this.relationsLabel[step])).reduce(
            (memo, item) => ({ ...memo, [item]: "" }),
            {},
          ),
        ];
        this.tabsIndex[step] = `${this.studentData[step].length - 1}`;
      }
    },

    removeTab(index) {
      const { step } = this;

      const newArr = [...this.studentData[step]];
      newArr.splice(+index, 1);
      this.studentData[step] = newArr;
      this.tabsIndex = {
        ...this.tabsIndex,
        [step]: +this.tabsIndex[step] ? `${+this.tabsIndex[step] - 1}` : "0",
      };
    },

    getObjUrl(file) {
      return URL.createObjectURL(file);
    },

    submit() {
      if (this.validate()) {
        const family = [];

        if (Object.values(this.studentData.father).filter(Boolean).length) {
          family.push({
            ...this.convertFamily(this.studentData.father),
            type: "FA",
          });
        }

        if (Object.values(this.studentData.mother).filter(Boolean).length) {
          family.push({
            ...this.convertFamily(this.studentData.mother),
            type: "MO",
          });
        }

        this.studentData.brothers.forEach(brother => family.push({
          ...this.convertFamily(brother),
          type: "BR",
        }));

        this.studentData.sisters.forEach(sister => family.push({
          ...this.convertFamily(sister),
          type: "SI",
        }));

        const reader = new FileReader();

        const data = {
          ...this.studentData.about,
          ...this.studentData.milspecialty,
          birth_info: this.studentData.birthInfo,
          contact_info: this.studentData.contactInfo,
          passport: this.studentData.passport,
          recruitment_office: this.studentData.recruitmentOffice,
          university_info: this.studentData.universityInfo,
          family,
          generate_documents: true,
        };

        reader.onload = async() => {
          data.image = reader.result;

          try {
            await postStudent(data);
            this.formSubmitted = true;
          } catch (e) {
            this.$alert(
              "Проверьте правильность заполненных данных. Если проблема не решится, отправьте текст ошибки нам на почту: <a href=\"mailto:dal.mec.hse@gmail.com\">dal.mec.hse@gmail.com</a>",
              "Не удалось отправить форму",
              {
                confirmButtonText: "Скопировать текст ошибки",
                type: "error",
                dangerouslyUseHTMLString: true,
                callback: async() => {
                  const dataToCopy = e.response
                    ? _pick(e.response, ["config", "data"])
                    : { config: e.config };

                  dataToCopy.config.data = _omit(JSON.parse(dataToCopy.config.data), ["image"]);

                  if (await copyToClipboard(JSON.stringify(dataToCopy, null, 4))) {
                    this.$message({
                      type: "success",
                      message: "Текст скопирован",
                    });
                  } else {
                    this.$message({
                      type: "error",
                      message: "Текст не скопирован",
                    });
                  }
                },
              },
            );
          }

          reader.onerror = () => {
            this.isSubmitting = false;
            console.error("Ошибка чтения файла:", reader.error);
            this.$message({
              type: "error",
              message: "Ошибка чтения файла",
            });
          };

          this.isSubmitting = false;
        };

        try {
          this.isSubmitting = true;
          reader.readAsDataURL(this.studentData.photo.photo[0].raw);
        } catch (e) {
          this.isSubmitting = false;
          console.error("Ошибка чтения файла:", e);
          this.$message({
            type: "error",
            message: "Ошибка чтения файла",
          });
        }
      }
    },
  },
};
</script>

<style lang="scss" module>
.header {
  margin-bottom: 30px;

  .title {
    margin-bottom: 20px;
  }
}

.root {
  display: flex;
  max-width: 600px;
  min-height: 100vh;
  margin: auto;
  padding: 20px 10px;
  flex-direction: column;
  justify-content: space-between;
}

.thanks {
  display: flex;
  align-items: center;
  justify-content: center;
  flex: 1;
}

.footer {
  margin-top: 35px;
  border-top: 1px solid #cfc8c8;
  color: #cfc8c8;
  padding-top: 10px;

  a {
    color: #5a96d6;
  }
}
</style>
