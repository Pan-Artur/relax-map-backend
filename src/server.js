import express from "express";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import YAML from "yaml";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const app = express();

app.use(cors());
app.use(express.json());

const filename = fileURLToPath(import.meta.url);
const dirname = path.dirname(filename);

const swaggerPath = path.join(dirname, "../docs/openapi.yaml");
const swaggerFile = fs.readFileSync(swaggerPath, "utf8");
const swaggerDoc = YAML.parse(swaggerFile);

app.use("/swagger", swaggerUi.serve, swaggerUi.setup(swaggerDoc));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Swagger: http://localhost:${PORT}/swagger`);
});
