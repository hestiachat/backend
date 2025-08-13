import express, { Response, Request } from 'express';
import asyncHandler from 'express-async-handler';
import router from './auth';

// The correct way is to define a route handler with (req, res) and use router.get(path, handler)
router.get('/', asyncHandler(async (req: Request, res: Response) => {
    res.send('API Is working!');
}));

export default router;