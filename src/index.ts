import { Request,Response,NextFunction } from 'express'
import  express  from 'express'
import { Pool } from 'pg'
import bcrypt from 'bcrypt'
import path from 'path'
import jwt from 'jsonwebtoken'
import bodyParser from 'body-parser'

const jsonParser = bodyParser.json()
const secret = 'backend-Login-2024'
const app = express()
const port = 9999
const multer = require("multer")

var cors = require('cors')
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use('/images', express.static(path.join(__dirname, 'public/images')));

const pool = new Pool({
    user : 'postgres',
    host : 'localhost',
    database : 'dbBackend',
    password : '1234',
    port : 5432
})

interface RequestWithToken extends Request {
    token?: {
        email: string;
        firstname:string;
        lastname:string;
        id:string;
    };
}
  


const storage = multer.diskStorage({
    destination : './public/images',
    filename : (req:Request,file:any,cb:any)=>{
        return cb(null,`${file.fieldname}_${Date.now()}${path.extname(file.originalname)}`)
    }
})


const upload = multer({
    storage: storage
})

const ifnotLogin = (req: RequestWithToken, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        res.status(401).send(`Unauthorized: You are not logged in.`);
    } else {
        try {
            const verify = jwt.verify(token, secret) as { email: string; firstname: string; lastname: string; id:string };
            req.token = {
                email: verify.email,
                firstname: verify.firstname,
                lastname: verify.lastname,
                id: verify.id,
            };
            next();
        } catch (err) {
            res.status(401).send(`Unauthorized: Invalid token.`);
        }
    }
};


app.get('/mainpage', ifnotLogin, async (req: RequestWithToken, res: Response) => {
    if (req.token) {
        res.send(`hi ${req.token.email}`);
    } else {
        res.status(401).send(`Unauthorized: Invalid token.`);
    }
});


app.post('/register',async(req:Request,res:Response)=>{
    const client = await pool.connect()
    try {
    const hashPassword = await bcrypt.hash(req.body.password,10)
    const checkEmail = await client.query('SELECT * FROM users WHERE email = $1',[req.body.email])
    if(checkEmail.rows.length === 0){
        const result = await client.query('INSERT INTO users (email,password,firstname,lastname) values($1,$2,$3,$4) RETURNING *',[req.body.email,hashPassword,req.body.firstname,req.body.lastname])
        return res.send(`Complete Register`)
    }else{
        return res.send(`Email has already been used`)
    }

    } catch (error) {
        res.send(error)
    }finally{
        client.release()
    }
})

app.post('/login', jsonParser, async (req: Request, res: Response) => {
    const client = await pool.connect();
    try {
        const checkEmail = await client.query('SELECT * FROM users WHERE email = $1', [req.body.email]);

        if (checkEmail.rows.length === 0) {
            return res.send(`email or password is incorrect`);
        }

        const user = checkEmail.rows[0];
        const passwordMatch = await bcrypt.compare(req.body.password, user.password);

        if (passwordMatch) {
            if (secret) {
                const token = jwt.sign({ email: user.email, firstname: user.firstname, lastname:user.lastname, id:user.id }, secret, { expiresIn: '1h' });
                res.send({ token, message: 'Login Success' });
            } else {
                res.status(500).send('Internal Server Error: Secret is undefined');
            }
        } else {
            res.send(`email or password is incorrect`);
        }
    } catch (error) {
        res.send(error);
    } finally {
        client.release();
    }
});

app.post('/authen', jsonParser, (req: Request, res: Response) => {
    try {
        const authorizationHeader = req.headers.authorization;

        if (authorizationHeader !== undefined) {
            const token = authorizationHeader.split(' ')[1];
            const decoded = jwt.verify(token, secret);
            res.json({ status: 'ok', decoded });
        } else {
            res.json({ status: 'error', message: 'Authorization header is undefined' });
        }
    } catch (err) {
        res.json({ status: 'error', message: err });
    }
});



app.delete('/deleteUser/:id',async (req:Request,res:Response)=>{
    const client = await pool.connect()
    try {
        const checkid = await client.query('SELECT id FROM users WHERE id = $1',[req.params.id])
        if(checkid){
            const result = await client.query('DELETE FROM users WHERE id = $1',[req.params.id])
            return res.send(`Delete ID ${req.params.id} Complete`)
        }else{
            return res.send(`ID ${req.params.id} Not found`)
        }
    } catch (error) {
        return res.send(error)
    }
})

app.put('/changePassword/:id', async (req: Request, res: Response) => {
    const client = await pool.connect();
  
    try {
      const hashPassword = await bcrypt.hash(req.body.password, 10);
  
      const checkid = await client.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
  
      if (checkid.rows.length > 0) {
        const result = await client.query('UPDATE users SET password = $1 WHERE id = $2 RETURNING *', [
          hashPassword,
          req.params.id,
        ]);
  
        return res.send('Update password success');
      } else {
        return res.status(404).send('User not found');
      }
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    } finally {
      client.release();
    }
  });


  app.post('/post', ifnotLogin, upload.single('images'), async (req:RequestWithToken, res:Response) => {
    const client = await pool.connect();
    try {   
      const result = await client.query('INSERT INTO post(content , postowner, userid , images) VALUES ($1, $2, $3, $4) RETURNING *', [req.body.content, req.token?.firstname,req.token?.id, req.file?.filename])
      return res.send(`Post Complete`);
    } catch (error) {
      return res.send(error);
    } finally {
      client.release();
    }
  });

  app.put('/updatePost/:id',ifnotLogin,async(req:RequestWithToken, res:Response)=>{
    const client = await pool.connect()
    try {
        const result = await client.query('UPDATE post SET content = $1 WHERE id = $2 RETURNING *',[req.body.content,req.params.id])
        return res.send(`update complete`)
    } catch (error) {
        return res.send(error)
    }finally{
        client.release()
    }
  })


app.get('/getPost/:id',async(req:RequestWithToken,res:Response)=>{
    const client = await pool.connect()
    try {
        const post = await client.query('SELECT * FROM post WHERE id = $1',[req.params.id])
        const resultPost = post.rows[0]


        res.send(
            `PostOwnet : ${resultPost.postowner}
             Date : ${resultPost.date}
             Content : ${resultPost.content}
             images : ${resultPost.images}
            `
        )
    } catch (error) {
        res.send(error)
    }
})





app.post('/comment/:id',ifnotLogin,async(req:RequestWithToken,res:Response)=>{
    const client = await pool.connect()
    try {
        const checkid = await client.query('SELECT id FROM post WHERE id = $1',[req.params.id])
        if(checkid.rows.length > 0){
            const result = await client.query('INSERT INTO comment (content,owner,userid,postid) VALUES($1,$2,$3,$4) RETURNING *',[req.body.content,req.token?.firstname,req.token?.id,req.params.id])
            const updatePostResult = await client.query('UPDATE post SET countcom = countcom + 1 WHERE id = $1 RETURNING *', [req.params.id]);
            return res.send(`comment complete`)
        }else{
            return res.send(`ID ${req.params.id} Not found`)
        }

    } catch (error) {
        return res.send(error)
    }finally{
        client.release()
    }
})

app.post('/replyComment/:id',ifnotLogin,async(req:RequestWithToken,res:Response)=>{
    const client = await pool.connect()
    try {
        const checkid = await client.query('SELECT id FROM comment WHERE id = $1',[req.params.id])
        if(checkid.rows.length > 0){
            const result = await client.query('INSERT INTO replycomment (content,owner,userid,postid) VALUES($1,$2,$3,$4) RETURNING *',[req.body.content,req.token?.firstname,req.token?.id,req.params.id])
            const post = await client.query('SELECT * FROM comment WHERE id = $1',[req.params.id])
            const IDpost = post.rows[0].postid
            const updatePostResult = await client.query('UPDATE post SET countcom = countcom + 1 WHERE id = $1 RETURNING *', [IDpost]);
            return res.send(`ReplyComment complete`)
        }else{
            return res.send(`ID ${req.params.id} Not found`)
        }

    } catch (error) {
        return res.send(error)
    }finally{
        client.release()
    }
})

app.put('/like/:id',ifnotLogin,async(req:RequestWithToken,res:Response)=>{
    const client = await pool.connect()
    try {
        const checkid = await client.query('SELECT id FROM post WHERE id = $1',[req.params.id])
        const checkOwnerlike = await client.query('SELECT ARRAY(SELECT unnest(ownerlike::text[])) as ownerlike_array FROM post WHERE id = $1', [req.params.id]);
        const ownerlikeArray = checkOwnerlike.rows[0].ownerlike_array;
        
        // ตรวจสอบว่าค่าใหม่มีอยู่ใน ownerlikeArray หรือไม่
        if (ownerlikeArray.includes(req.token?.firstname)) {

            const removeOwner = await client.query(`
            UPDATE post
            SET ownerlike = ARRAY(SELECT x FROM unnest(ownerlike) x WHERE x IS DISTINCT FROM $1)
            WHERE ownerlike @> ARRAY[$1]
            RETURNING *;
          `, [req.token?.firstname]);

          const unlike = await client.query('UPDATE post SET reaction = reaction - 1 WHERE id = $1 RETURNING *',[req.params.id])
            
          res.send(`unlike`);


        } else {

            const addOwner = await client.query('UPDATE post SET ownerlike = ARRAY_APPEND(ownerlike, $1) WHERE id = $2 RETURNING *', [req.token?.firstname, req.params.id]);
            const like = await client.query('UPDATE post SET reaction = reaction + 1 WHERE id = $1 RETURNING *',[req.params.id])
            res.send(`like`);
        }


    } catch (error) {
        return res.send(error)
    }finally{
        client.release()
    }
})

app.put('/likeComment/:id',ifnotLogin,async(req:RequestWithToken,res:Response)=>{
    const client = await pool.connect()
    try {
        const checkid = await client.query('SELECT id FROM comment WHERE id = $1',[req.params.id])
        const checkOwnerlike = await client.query('SELECT ARRAY(SELECT unnest(ownerlike::text[])) as ownerlike_array FROM comment WHERE id = $1', [req.params.id]);
        const ownerlikeArray = checkOwnerlike.rows[0].ownerlike_array;
        
        // ตรวจสอบว่าค่าใหม่มีอยู่ใน ownerlikeArray หรือไม่
        if (ownerlikeArray.includes(req.token?.firstname)) {

            const removeOwner = await client.query(`
            UPDATE comment
            SET ownerlike = ARRAY(SELECT x FROM unnest(ownerlike) x WHERE x IS DISTINCT FROM $1)
            WHERE ownerlike @> ARRAY[$1]
            RETURNING *;
          `, [req.token?.firstname]);

          const unlike = await client.query('UPDATE comment SET reaction = reaction - 1 WHERE id = $1 RETURNING *',[req.params.id])
            
          res.send(`unlike`);


        } else {

            const addOwner = await client.query('UPDATE comment SET ownerlike = ARRAY_APPEND(ownerlike, $1) WHERE id = $2 RETURNING *', [req.token?.firstname, req.params.id]);
            const like = await client.query('UPDATE comment SET reaction = reaction + 1 WHERE id = $1 RETURNING *',[req.params.id])
            res.send(`like`);
        }


    } catch (error) {
        return res.send(error)
    }finally{
        client.release()
    }
})


app.put('/likeReplyComment/:id',ifnotLogin,async(req:RequestWithToken,res:Response)=>{
    const client = await pool.connect()
    try {
        const checkid = await client.query('SELECT id FROM replycomment WHERE id = $1',[req.params.id])
        const checkOwnerlike = await client.query('SELECT ARRAY(SELECT unnest(ownerlike::text[])) as ownerlike_array FROM replycomment WHERE id = $1', [req.params.id]);
        const ownerlikeArray = checkOwnerlike.rows[0].ownerlike_array;
        
        // ตรวจสอบว่าค่าใหม่มีอยู่ใน ownerlikeArray หรือไม่
        if (ownerlikeArray.includes(req.token?.firstname)) {

            const removeOwner = await client.query(`
            UPDATE replycomment
            SET ownerlike = ARRAY(SELECT x FROM unnest(ownerlike) x WHERE x IS DISTINCT FROM $1)
            WHERE ownerlike @> ARRAY[$1]
            RETURNING *;
          `, [req.token?.firstname]);

          const unlike = await client.query('UPDATE replycomment SET reaction = reaction - 1 WHERE id = $1 RETURNING *',[req.params.id])
            
          res.send(`unlike`);


        } else {

            const addOwner = await client.query('UPDATE replycomment SET ownerlike = ARRAY_APPEND(ownerlike, $1) WHERE id = $2 RETURNING *', [req.token?.firstname, req.params.id]);
            const like = await client.query('UPDATE replycomment SET reaction = reaction + 1 WHERE id = $1 RETURNING *',[req.params.id])
            res.send(`like`);
        }


    } catch (error) {
        return res.send(error)
    }finally{
        client.release()
    }
})


app.delete('/deletePost/:id', async (req: Request, res: Response) => {
  const client = await pool.connect();

  try {
    const checkid = await client.query('SELECT * FROM post WHERE id = $1', [req.params.id]);

    if (checkid.rows.length > 0) {
      const deletePost = await client.query('DELETE FROM post WHERE id = $1', [req.params.id]);

      const postidResult = await client.query('SELECT id FROM comment WHERE postid = $1', [req.params.id]);

      if (postidResult.rows.length > 0) {
        const postIdToDelete = postidResult.rows[0].id;

        const deleteReply = await client.query('DELETE FROM replycomment WHERE postid = $1', [postIdToDelete]);
        const deleteComment = await client.query('DELETE FROM comment WHERE id = $1', [postIdToDelete]);
      }

      return res.send(`Delete ID ${req.params.id} Complete`);
    } else {
      return res.status(404).send(`ID ${req.params.id} Not found`);
    }
  } catch (error) {
    console.error(error);
    return res.status(500).send('Internal Server Error');
  } finally {
    client.release();
  }
});

app.delete('/deleteComment/:id',async(req:Request,res:Response)=>{
    const client = await pool.connect();

    try {
        
        const checkid = await client.query('SELECT * FROM comment WHERE id = $1',[req.params.id])
        if(checkid.rows.length > 0){
            const comment = checkid.rows[0]
          
            
                const deleteComment = await client.query('DELETE FROM comment WHERE id = $1', [req.params.id])
                const deleteReply = await client.query('DELETE FROM replycomment WHERE postid = $1',[req.params.id])
            
           return res.send(`Delete ID ${req.params.id} Complete`)
                
            }else{
                return res.send(`ID ${req.params.id} Not found`)
            }


    } catch (error) {
       return res.send(error)
    }finally{
        client.release()
    }
})

app.delete('/deleteReply/:id',async(req:Request,res:Response)=>{
    const client = await pool.connect();

    try {
        
        const checkid = await client.query('SELECT * FROM replycomment WHERE id = $1',[req.params.id])
        if(checkid.rows.length > 0){
            const comment = checkid.rows[0]
          
           
                const deleteComment = await client.query('DELETE FROM replycomment WHERE id = $1', [req.params.id])
            
           return res.send(`Delete ID ${req.params.id} Complete`)
               
            }else{
                return res.send(`ID ${req.params.id} Not found`)
            }


    } catch (error) {
       return res.send(error)
    }finally{
        client.release()
    }
})

app.get('/profile', ifnotLogin, async (req: RequestWithToken, res: Response) => {
    const client = await pool.connect();
    
    try {
        const result = await client.query('SELECT * FROM users WHERE id = $1', [req.token?.id]);
        
        if (result.rows.length > 0) {
            const result1 = result.rows[0];
            const email = result1.email;
            const firstname = result1.firstname;
            const lastname = result1.lastname;
            
            res.json({ email, firstname, lastname });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    } finally {
        client.release();
    }
});

app.put('/updateProfile',ifnotLogin,async(req:RequestWithToken,res:Response)=>{
    const client = await pool.connect()
    try {
        const result = await client.query('SELECT * FROM users WHERE id = $1', [req.token?.id]);
        if(result.rows.length > 0){
            const update = await client.query('UPDATE users SET firstname = $1, lastname = $2 WHERE email = $3 RETURNING *',[req.body.firstname,req.body.lastname,req.token?.email])
            const updatePost = await client.query('UPDATE post SET postowner = $1 WHERE userid = $2 ',[req.body.firstname,req.token?.id])
            const updateComment = await client.query('UPDATE comment SET owner = $1 WHERE userid = $2 ',[req.body.firstname,req.token?.id])
            const updateReplyComment = await client.query('UPDATE replycomment SET owner = $1 WHERE userid = $2 ',[req.body.firstname,req.token?.id])
            return res.send(`update profile complete`)
        }else{
            return res.send(`ID ${req.params.id} Not found`)
        }
    } catch (error) {
        return res.send(error)
    }
})

app.put('/uploadProfile',ifnotLogin,upload.single('profile'),async(req:RequestWithToken,res:Response)=>{
    const client = await pool.connect()
    try {
        const images = await client.query('UPDATE users SET profile = $1 WHERE id = $2', [req.file?.filename, req.token?.id]);
        res.send(`upload profile success`);
    } catch (error) {
        return res.send(error)
    }
})

app.get('/imagesProfile',ifnotLogin,async(req:RequestWithToken,res:Response)=>{
    const client= await pool.connect()
    try {
        const checkid = await client.query('SELECT * FROM users WHERE id = $1',[req.token?.id])
        const profile = checkid.rows[0].profile
        res.send(profile)

    } catch (error) {
        
    }
})

app.listen(port,()=>{
    console.log(`server is running on port ${port}`)
})