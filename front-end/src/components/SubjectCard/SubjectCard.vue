<template>
  <div class="root" @click="selectSubject">
    <div>
      <div class="header">
        <CustomText
          variant="header"
          @click="selectSubject"
        >
          {{ title }}
        </CustomText>
        <div v-if="isMySubject" class="buttons">
          <img
            class="grow"
            src="../../assets/subject/edit.svg"
            alt=""
            @click="editSubject"
          >
          <img
            class="grow"
            src="../../assets/subject/close.svg"
            alt=""
            @click="deleteSubject"
          >
        </div>
      </div>
      <CustomText
        class="annotation"
        variant="paragraph"
        color="#333"
      >
        {{ annotation }}
      </CustomText>
    </div>
    <div class="owner">
      <img src="@/assets/subject/owner.svg" alt="">
      {{ owner }}
    </div>
  </div>
</template>

<script>
import CustomText from "@/common/CustomText";
import { deleteSubject } from "../../api/subjects";

export default {
  name: "SubjectCard",
  components: {
    CustomText,
  },
  props: {
    id: {
      type: Number,
      required: true,
    },
    title: {
      type: String,
      required: true,
    },
    annotation: {
      type: String,
      required: true,
    },
    owner: {
      type: String,
      required: true,
    },
    isMySubject: {
      type: Boolean,
      default: false,
    },
  },
  data() {
    return {
      editMode: false,
    };
  },
  methods: {
    selectSubject(e) {
      if (e.target.nodeName === "IMG") return;
      this.$router.push({ path: `/subjects/${this.id}/` });
    },
    editSubject() {
      this.$emit("edit", this.id);
    },
    deleteSubject() {
      this.$confirm(
        "Вы уверены, что хотите удалить дисциплину? Это действие не обратимо.",
        "Подтверждение",
        {
          confirmButtonText: "Да",
          cancelButtonText: "Отмена",
          type: "warning",
        },
      ).then(() => {
        deleteSubject(this.id)
          .then(() => {
            this.$emit("deleted", this.id);
          })
          .catch(err => {
            console.log(
              `delete of subject with id: ${this.id} FAILED. Error: ${err}`,
            );
          });
      });
    },
  },
};
</script>

<style scoped lang="scss">
@import "style";
</style>
