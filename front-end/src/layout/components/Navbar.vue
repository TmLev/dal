<template>
  <div class="mynavbar">
    <div
      class="burger"
      :title="isCollapse ? 'Развернуть меню' : 'Свернуть меню'"
      @click="toggleSideBar"
    >
      <Hamburger :is-active="sidebar.opened" class="hamburger-container" />
    </div>
    <Breadcrumb class="breadcrumb-container" />

    <div class="right-menu">
      <el-dropdown class="avatar-container" trigger="click">
        <div class="avatar-wrapper m-0" style="font-size: 19px">
          <!--          <img :src="avatar+'?imageView2/1/w/80/h/80'" class="user-avatar">-->
          {{ email }}
          <i class="el-icon-caret-bottom" />
        </div>
        <el-dropdown-menu slot="dropdown" class="user-dropdown">
          <router-link to="/">
            <el-dropdown-item> Домой </el-dropdown-item>
          </router-link>
          <el-dropdown-item divided>
            <span style="display: block" @click="logout">Выход</span>
          </el-dropdown-item>
        </el-dropdown-menu>
      </el-dropdown>
    </div>
  </div>
</template>

<script>
import { mapGetters } from "vuex";
import Breadcrumb from "@/components/Breadcrumb";
import LocalStorageService from "@/utils/LocalStorageService";
import Hamburger from "@/components/Hamburger";
import { surnameWithInitials } from "@/utils/person";

export default {
  components: {
    Breadcrumb,
    Hamburger,
  },
  computed: {
    ...mapGetters(["sidebar", "email"]),
    isCollapse() {
      return !this.sidebar.opened;
    },
  },
  methods: {
    surnameWithInitials,
    logout() {
      const localStorageService = LocalStorageService.getService();
      localStorageService.clearToken();
      this.$router.push("/login");
    },
    toggleSideBar() {
      this.$store.dispatch("app/toggleSideBar");
    },
  },
};
</script>

<style lang="scss" scoped>
.mynavbar {
  display: flex;
  height: 56px;
  overflow: hidden;
  position: relative;
  box-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
  background-color: #2d3746;
  color: #fff !important;

  .breadcrumb-container {
    height: 56px;
    display: flex;
    align-items: center;
    align-items: center;
    float: left;
    color: #fff;
    color: #fff !important;
  }

  .right-menu {
    margin-right: 120px;
    margin-left: auto;
    height: 100%;
    line-height: 56px;

    &:focus {
      outline: none;
    }

    .right-menu-item {
      display: inline-block;
      padding: 0 8px;
      height: 100%;
      font-size: 18px;
      color: #fff !important;
      vertical-align: text-bottom;

      &.hover-effect {
        cursor: pointer;
        transition: background 0.3s;

        &:hover {
          background: rgba(0, 0, 0, 0.025);
        }
      }
    }

    .avatar-container {
      margin-right: 30px;

      .avatar-wrapper {
        margin-top: 5px;
        position: relative;
        color: #fff !important;

        .user-avatar {
          cursor: pointer;
          width: 40px;
          height: 40px;
          border-radius: 10px;
        }

        .el-icon-caret-bottom {
          cursor: pointer;
          position: absolute;
          right: -20px;
          top: 25px;
          font-size: 12px;
        }
      }
    }
  }
}

.burger {
  display: flex;
  align-items: center;
  height: 56px;
  padding: 20px;
  justify-content: space-between;
  cursor: pointer;

  &:hover {
    background-color: #263445;
  }
}
</style>
