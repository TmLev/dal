<template>
  <div :class="$style.root">
    <h1>Прием документов</h1>

    <div v-loading="loading">
      <el-row class="filter-row" :gutter="20">
        <el-col :span="10">
          <TextInput
            v-model="searchQuery"
            :class="$style.input"
            placeholder="Введите ФИО студента"
            @change="search"
          />
        </el-col>
        <el-col v-if="campuses.length > 1" :offset="6" :span="4">
          <el-select
            v-model="selectedCampus"
            placeholder="Кампус"
            @change="changeCampus"
          >
            <el-option
              v-for="item in campuses"
              :key="item"
              :label="item | campusFilter"
              :value="item"
            />
          </el-select>
        </el-col>
        <el-col v-else :offset="7" :span="3">
          <el-tag type="info" class="custom-tag">
            {{ campuses[0] | campusFilter }}
          </el-tag>
        </el-col>
        <el-col :span="4">
          <el-tag
            class="custom-tag"
            type="info"
          >
            Всего абитуриентов: {{ entriesAmount }}
          </el-tag>
        </el-col>
      </el-row>

      <InfoTable
        :key="`${currentPage}-${entriesAmount}`"
        :class="$style.table"
        :data="data"
        :start-index="(currentPage - 1) * pageSize"
        @update="onUpdate"
      />

      <div :class="$style.pagination">
        <el-pagination
          layout="sizes, prev, pager, next, jumper"
          :total="entriesAmount"
          :current-page="currentPage"
          :page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          @current-change="fetchData"
          @size-change="onPageSizeChange"
        />
      </div>
    </div>
  </div>
</template>

<script>
import _debounce from "lodash/debounce";
import moment from "moment";
import { mapGetters } from "vuex";

import { getApplicationsStudents, updateStudentApplicationInfo } from "@/api/students";

import { TextInput } from "@/common/inputs";
import InfoTable from "@/components/@ApplicantsDocuments/Table.vue";

export default {
  name: "ApplicantsDocuments",
  components: {
    InfoTable,
    TextInput,
  },
  filters: {
    campusFilter(campus) {
      switch (campus) {
        case "MO":
          return "Москва";
        case "SP":
          return "Санкт-Петербург";
        case "NN":
          return "Нижний Новгород";
        case "PE":
          return "Пермь";
        default:
          return "Ошибка";
      }
    },
  },
  data() {
    const selectedCampus = this.$store.state.user.campuses.length > 0
      ? this.$store.state.user.campuses[0]
      : "MO";
    return {
      data: [],
      entriesAmount: 0,
      currentPage: 1,
      pageSize: 50,
      searchQuery: "",
      loading: false,
      selectedCampus,
    };
  },
  computed: {
    ...mapGetters(["campuses"]),
  },
  created() {
    this.fetchData();
  },
  methods: {
    async changeCampus(campus) {
      this.selectedCampus = campus;
      await this.fetchData();
    },
    async fetchData(page = 1) {
      this.currentPage = page || 1;
      this.loading = true;
      const { data } = await getApplicationsStudents(
        this.currentPage,
        this.pageSize,
        {
          search: this.searchQuery,
          campus: this.selectedCampus,
        },
      );
      this.data = data.results.map(item => ({
        id: item.id,
        fullname: item.full_name,
        birthday: moment(item.birth_date).format("DD.MM.yyyy"),
        passport: item.passport,
        program: item.program_code,
        faculty: item.faculty,
        ...item.application_process,
      }));
      this.entriesAmount = data.count;
      this.loading = false;
    },

    async onPageSizeChange(pageSize) {
      this.pageSize = pageSize;
      await this.fetchData();
    },

    async onUpdate({ id, key, value }) {
      try {
        await updateStudentApplicationInfo(id, { [key]: value });
      } catch (e) {
        console.error("Не удалось обновить данные студента о поступлении: ", e);
        this.$message.error(
          "Не удалось обновить данные, рекомендуем перезагрузить страницу",
        );
      }
    },

    search: _debounce(function debouncedFetch() {
      this.fetchData();
    }, 750),
  },
};
</script>

<style lang="scss" module>
.root {
  padding: 50px;
}

.label {
  height: 150px;
  word-break: break-word !important;

  &.verticalText {
    writing-mode: vertical-rl;
  }
}

.table {
  margin-top: 20px;
}

.pagination {
  margin-top: 20px;
}
</style>

<style lang="scss" scoped>
.filter-row {
  margin-top: 20px;
  display: flex;
  flex-direction: row;
  align-items: center;
}

.custom-tag {
  font-size: 1em;
}
</style>
