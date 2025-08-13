import * as admin from "firebase-admin";
// @ts-ignore
import serviceAccount from "../firebaseServiceAccount.json";

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount as admin.ServiceAccount)
});

export default admin;