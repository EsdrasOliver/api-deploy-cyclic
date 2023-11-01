import jwt from 'jsonwebtoken'
import { NextFunction, Request, Response } from "express";
import { UnauthorizedError } from "../helpers/api-erros";
import { userRepository } from "../repositories/userRepository";

type jwtPayload = {
    id: number
}

export const authMiddleware = async (req: Request, res: Response, next: NextFunction) =>  {
    const {authorization} = req.headers

    if(!authorization) throw new UnauthorizedError('Não autorizada')

    const token = authorization.split(' ')[1]

    const {id} = jwt.verify(token, process.env.JWT_PASS ?? '') as jwtPayload

    const user = await userRepository.findOneBy({id})

    if(!user) throw new UnauthorizedError('Não autorizado')

    const {password: _, ...loggedUser} = user

    req.user = loggedUser

    next()
}