<template>
  <div>
    <div class="my-advanced-search" @click="advancedClick">
      <div class="d-flex align-items-center">
        <div class="my-advanced-search-text" style="cursor: pointer">
          Расширенный поиск
        </div>
        <img
          src="../../assets/scienceWorks/dropdown.svg"
          alt=""
          class="my-advanced-search-arrow ml-2"
        >
      </div>
    </div>
    <div class="filters mt-3 pt-3 pb-3" style="display: none">
      <el-row class="">
        <el-col :span="10" :offset="1">
          <div class="filters-title pl-1">
            Автор
          </div>
          <el-select
            v-model="author"
            clearable
            placeholder="Все авторы"
            class="filters-select"
            @change="updateQuery"
          >
            <el-option
              v-for="item in authors"
              :key="item.id"
              :value="item.id"
              :label="surnameWithInitials(item)"
            />
          </el-select>
        </el-col>
        <el-col :span="10" :offset="1">
          <div class="filters-title pl-1">
            Размещение
          </div>
          <el-select
            v-model="publisher"
            clearable
            placeholder="Все размещения"
            class="filters-select"
            @change="updateQuery"
          >
            <el-option
              v-for="{ id, name } in publishers"
              :key="id"
              :value="id"
              :label="name"
            />
          </el-select>
        </el-col>
      </el-row>
      <el-row class="mt-3">
        <el-col :offset="1" :span="10">
          <div class="filters-title pl-1">
            Период публикации
          </div>
          <el-date-picker
            v-model="valueDate"
            type="daterange"
            align="right"
            unlink-panels
            start-placeholder="Начало"
            end-placeholder="Конец"
            @change="updateQuery"
          />
        </el-col>
      </el-row>
    </div>
  </div>
</template>

<script>
import { getAuthors } from "@/api/authors";
import { getPublishers } from "@/api/publishers";
import moment from "moment";
import { mapActions } from "vuex";
import { surnameWithInitials } from "@/utils/person";

export default {
  name: "AdvancedPaperSearch",
  components: {},
  data() {
    return {
      authors: [],
      author: null,
      publishers: [],
      publisher: null,
      valueDate: "",
    };
  },
  mounted() {
    if (this.$store.getters.authors.length === 0) {
      getAuthors()
        .then(response => {
          this.authors = response.data;
          this.setAuthors(this.authors);
        })
        .catch(() => {
          console.log("Данные по авторам не указаны");
        });
    } else {
      this.authors = this.$store.getters.authors;
    }

    if (this.$store.getters.publishers.length === 0) {
      getPublishers()
        .then(response => {
          this.publishers = response.data;
          this.setPublishers(this.publishers);
        })
        .catch(() => {
          console.log("Данные по размещениям не указаны");
        });
    } else {
      this.publishers = this.$store.getters.publishers;
    }
  },
  methods: {
    surnameWithInitials,
    ...mapActions({
      setAuthors: "documents/setAuthors",
      setPublishers: "documents/setPublishers",
    }),
    advancedClick() {
      const filters = document.querySelector(".filters");
      const array = document.querySelector(".my-advanced-search-arrow");
      if (filters.style.display === "none") {
        filters.style.display = "block";
        array.style.transform = "rotate(180deg)";
      } else {
        filters.style.display = "none";
        array.style.transform = "rotate(0deg)";
      }
    },

    updateQuery() {
      const query = {
        authors: this.author,
        category: this.$route.query.category,
        publishers: this.publisher,
        search: this.$route.query.search,
      };

      if (this.valueDate) {
        query.start_date = moment(this.valueDate[0]).format("YYYY-MM-DD");
        query.end_date = moment(this.valueDate[1]).format("YYYY-MM-DD");
      }

      this.$router.push({ query });
    },
  },
};
</script>

<style scoped lang="scss">
@import "papers-advanced";
</style>
