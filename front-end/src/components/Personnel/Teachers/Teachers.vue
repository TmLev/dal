<template>
  <div>
    <el-row class="filterRow" :gutter="20" style="margin-bottom: 15px">
      <el-col :span="8">
        <el-input
          v-model="filter.search"
          clearable
          placeholder="Поиск..."
          @clear="onFilter"
          @keyup.native.enter="onFilter"
        />
      </el-col>
      <el-col :span="7">
        <el-select
          v-model="filter.milfaculty"
          clearable
          placeholder="Выберите цикл"
          style="display: block"
          @change="onFilter"
        >
          <el-option
            v-for="item in milfaculties"
            :key="item"
            :label="item"
            :value="item"
          />
        </el-select>
      </el-col>
      <el-col :offset="7" :span="2">
        <el-button type="text" @click="clearFilter">
          Сбросить
        </el-button>
      </el-col>
    </el-row>
    <el-row class="table">
      <el-table
        v-loading="loading"
        max-height="600px"
        :data="teachers"
        :default-sort="{ prop: 'fullname', order: 'descending' }"
        stripe
      >
        <el-table-column
          width="400px"
          prop="fullname"
          label="ФИО"
          sortable
        />
        <el-table-column prop="milfaculty" label="Цикл" sortable />
        <el-table-column prop="rank" label="Звание" />
        <el-table-column prop="teacher_post" label="Должность" />
        <el-table-column prop="milgroup.milgroup" label="Прикр. взвод" />
        <el-table-column label="" width="120px">
          <template slot-scope="scope">
            <el-button
              size="mini"
              icon="el-icon-edit"
              type="info"
              circle
              @click="onEdit(scope.row)"
            />
            <el-button
              size="mini"
              icon="el-icon-delete"
              type="danger"
              circle
              @click="onDelete(scope.row.id)"
            />
          </template>
        </el-table-column>
      </el-table>
    </el-row>
    <Teacher
      v-model="modal"
      :teacher="editTeacher"
      @closeModal="closeModal"
      @submitModal="clearFilter"
    />
  </div>
</template>

<script>
import { getTeacher, deleteTeacher } from "@/api/teachers";
import moment from "moment";
import { getError, deleteError, deleteSuccess } from "@/utils/message";
import Teacher from "../Teacher/Teacher.vue";

export default {
  name: "Teachers",
  components: {
    Teacher,
  },
  data() {
    return {
      loading: false,
      filter: {
        search: null,
        milfaculty: null,
      },
      teachers: [],
      modal: false,
      milgroups: [
        {
          milgroup: 1807,
          milfaculty: "ВКС",
        },
        {
          milgroup: 1808,
          milfaculty: "ВКС",
        },
        {
          milgroup: 1809,
          milfaculty: "ВКС",
        },
      ],
      milfaculties: ["Разведка", "Сержанты", "ВКС", "РВСН"],
      editTeacher: null,
    };
  },
  async created() {
    await this.onFilter();
  },
  methods: {
    formatDate(d) {
      if (d) return moment(d.date).format("DD.MM.YYYY");
      return "Нет данных";
    },
    closeModal() {
      this.modal = false;
      document
        .getElementById("main-container")
        .classList.remove("stop-scrolling");
      this.editTeacher = {};
    },
    openModal() {
      this.modal = true;
      document.getElementById("main-container").classList.add("stop-scrolling");
    },
    async onFilter() {
      try {
        this.loading = true;
        this.teachers = (await getTeacher(this.filter)).data;
      } catch (err) {
        getError("преподавателей", err.response.status);
      } finally {
        this.loading = false;
      }
    },
    async clearFilter() {
      Object.keys(this.filter).forEach(key => {
        this.filter[key] = null;
      });
      await this.onFilter();
    },
    onDelete(id) {
      this.$confirm(
        "Вы уверены, что хотите удалить преподавателя?",
        "Подтверждение",
        {
          confirmButtonText: "Да",
          cancelButtonText: "Отмена",
          type: "warning",
        },
      ).then(async() => {
        try {
          await deleteTeacher(id);
          this.onFilter();
          deleteSuccess("преподавателя");
        } catch (err) {
          deleteError("преподавателя", err.response.status);
        }
      });
    },
    onEdit(row) {
      this.editTeacher = { ...row };
      this.openModal();
    },
  },
};
</script>

<style scoped lang="less"></style>
