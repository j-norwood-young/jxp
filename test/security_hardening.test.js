const path = require("path");
const chai = require("chai");
const chaiHttp = require("chai-http");
const should = chai.should();
const init = require("./init");
const security = require("../dist/libs/security");

const model_dir = process.env.MODEL_DIR
	? path.resolve(process.cwd(), process.env.MODEL_DIR)
	: path.join(process.cwd(), "dist/models");
const testMod = require(path.join(model_dir, "test_model"));
const Test = testMod.default || testMod;

const server = require("../dist/bin/server");

chai.use(chaiHttp);

describe("security hardening", () => {
	let apikey = null;

	before(async function () {
		// init + bcrypt login exceeds the suite's 1s default on slower CI runners.
		this.timeout(10000);
		await init.init();
		const loginRes = await chai.request(server)
			.post("/login")
			.send({ email: init.email, password: init.password });
		loginRes.should.have.status(200);
		const record = await security.generateApiKey(loginRes.body.user_id);
		apikey = record.apikey;
	});

	it("rejects /call for unlisted static", (done) => {
		chai.request(server)
			.post("/call/test/notAllowed")
			.set("X-API-Key", apikey)
			.send({})
			.end((err, res) => {
				res.should.have.status(403);
				done();
			});
	});

	it("allows /call for listed static", (done) => {
		chai.request(server)
			.post("/call/test/test")
			.set("X-API-Key", apikey)
			.send({})
			.end((err, res) => {
				res.should.have.status(200);
				done();
			});
	});

	it("rejects filter with $where", (done) => {
		chai.request(server)
			.get('/api/test?filter[$where]=true&limit=10')
			.set("X-API-Key", apikey)
			.end((err, res) => {
				res.should.have.status(400);
				done();
			});
	});

	it("rejects filter with $expr", (done) => {
		chai.request(server)
			.get('/api/test?filter[$expr][$eq][0]=$foo&filter[$expr][$eq][1]=bar&limit=10')
			.set("X-API-Key", apikey)
			.end((err, res) => {
				res.should.have.status(400);
				done();
			});
	});

	it("allows $expr in aggregate $match", (done) => {
		chai.request(server)
			.post("/aggregate/test")
			.set("X-API-Key", apikey)
			.send({
				query: [
					{
						$match: {
							$expr: {
								$gte: [
									"$createdAt",
									{ $dateFromString: { dateString: "2020-01-01T00:00:00.000Z" } },
								],
							},
						},
					},
					{ $group: { _id: null, count: { $sum: 1 } } },
				],
			})
			.end((err, res) => {
				res.should.have.status(200);
				res.body.data.should.be.an("array");
				done();
			});
	});

	it("rejects $where in aggregate $match", (done) => {
		chai.request(server)
			.post("/aggregate/test")
			.set("X-API-Key", apikey)
			.send({
				query: [{ $match: { $where: "true" } }],
			})
			.end((err, res) => {
				res.should.have.status(400);
				done();
			});
	});

	it("strips password from list responses", (done) => {
		Test.deleteMany(() => {
			const item = new Test({ foo: "pw", bar: "pwbar", password: "secret" });
			item.save(() => {
				chai.request(server)
					.get("/api/user?limit=10")
					.set("X-API-Key", apikey)
					.end((err, res) => {
						res.should.have.status(200);
						if (res.body.data.length) {
							res.body.data[0].should.not.have.property("password");
						}
						done();
					});
			});
		});
	});

	it("rejects password_override without admin", (done) => {
		const userMod = require(path.join(model_dir, "user_model"));
		const User = userMod.default || userMod;
		const plain = new User({
			email: "nonadmin@test.local",
			name: "Non Admin",
			password: init.password,
			admin: false,
		});
		plain.save((err, saved) => {
			if (err) return done(err);
			chai.request(server)
				.put(`/api/user/${saved._id}?password_override=1`)
				.set("X-API-Key", apikey)
				.send({ password: "$2a$04$fakehash" })
				.end((err2, res) => {
					res.should.have.status(403);
					done();
				});
		});
	});
});
