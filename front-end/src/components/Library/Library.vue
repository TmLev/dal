<template>
  <div class="root">
    <PageHeader title="Библиотека" button="+ Добавить учебник" :click="addNewBook"/>
    <Modal
      :opened="showModal"
      :submit-callback="fetchData"
      @close-modal="showModal = false"
    />
    <SearchBar placeholder="Введите название книги" :search="searchBook" :delete="deleteSearchInput"/>
    <CustomText :mt="SIZES.m" variant="paragraph">Найдено: {{ books.length }}</CustomText>
    <el-row>
      <el-col :span="18">
        <div class="sort mt-3 mb-3">
          <CustomText variant="sub-header" :mr="SIZES.m">Сортировать</CustomText>
          <el-select
            v-model="sort"
            placeholder="Выберите тип причины"
            style="display: block"
          >
            <el-option
              v-for="item in sortTypes"
              :key="item.key"
              :label="item.label"
              :value="item.key"
            >
            </el-option>
          </el-select>
        </div>
        <div class="content" v-loading="loading">
          <div class="books">
            <div class="book" v-for="item in books" :key="item.id">
              <Book :data="item" />
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="5" :offset="1">
        <LibraryFilters :clear="clearHandler" />
      </el-col>
    </el-row>
  </div>
</template>

<script>
import {SIZES} from "@/utils/appConsts"
import PageHeader from "@/common/PageHeader";
import SearchBar from "@/common/SearchBar";
import Modal from "./LibraryModal.vue";
import CustomText from "@/common/CustomText";
import LibraryFilters from "@/components/LibraryFilters";
import Book from "@/components/Book";
import {getBooks} from "@/api/books";

export default {
  name: "Library",
  components: {
    LibraryFilters,
    CustomText,
    SearchBar,
    PageHeader,
    Book,
    Modal,
  },
  data() {
    return {
      SIZES,
      books: [],
      loading: false,
      sortTypes: [
        {
          key: '-publication_year',
          label: 'По году ↓'
        },
        {
          key: 'publication_year',
          label: 'По году ↑'
        },
        {
          key: '-title',
          label: 'По названию ↓'
        },
        {
          key: 'title',
          label: 'По названию ↑'
        }
      ],
      showModal: false,
    };
  },
  computed: {
    sort: {
      get() {return this.$route.query.sort || '-publication_year'},
      set(value) {
        this.$router.push({query: {
          ...this.$route.query,
          sort: value,
        }})
      }
    },
    search: {
      get() { return this.$route.query.search || '' },
      set(value) {
        this.$router.push({query: {
          ...this.$route.query,
          search: value,
        }})
      }
    }
  },
  mounted() {
    this.fetchData()
  },
  methods: {
    fetchData() {
      this.loading = true
      const {author, subject, year} = this.$route.query
      getBooks(this.lodash.pickBy({
        ordering: this.sort,
        authors: author,
        subjects: subject,
        end_year: year,
        start_year: year,
        search: this.search,
      })).then(res => {
        console.log('[BOOKS]: ', res.data)
        this.books = res.data
        this.loading = false
      })
    },
    addNewBook() {
      this.showModal = true
    },
    searchBook(value) { this.search = value },
    deleteSearchInput() { this.search = '' },
    clearHandler() {
      console.log('clearHandler func')
    }
  },
  watch: {
    $route() {
      this.fetchData()
    },
  },
}
</script>

<style scoped lang="scss">
@import "@/styles/variables.scss";

.root {

}

.sort {
  display: flex;
  align-items: center;
}

.content {
  min-height: 50vh;
}
</style>